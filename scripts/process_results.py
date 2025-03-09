import argparse
import json
import os
import sys
import yaml
from pathlib import Path


def parse_arguments():
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(description="Process ScanCode.io scan results")
    parser.add_argument("--input", required=True, help="Path to the ScanCode.io JSON output file")
    parser.add_argument("--policy", help="Path to policy configuration file")
    parser.add_argument("--generate-sbom", default="true", help="Generate enhanced SBOMs with vulnerability data")
    parser.add_argument("--sbom-format", default="both", help="SBOM format (spdx, cyclonedx, or both)")
    parser.add_argument("--fail-on-findings", default="false", help="Fail if findings match policy criteria")
    return parser.parse_args()


def load_scan_results(file_path):
    """Load and parse ScanCode.io JSON results."""
    try:
        with open(file_path, 'r') as f:
            return json.load(f)
    except (IOError, json.JSONDecodeError) as e:
        print(f"Error loading scan results: {e}")
        sys.exit(1)


def load_policy(file_path):
    """Load policy configuration from YAML file."""
    if not file_path or not os.path.exists(file_path):
        return None
    
    try:
        with open(file_path, 'r') as f:
            return yaml.safe_load(f)
    except (IOError, yaml.YAMLError) as e:
        print(f"Error loading policy file: {e}")
        return None


def extract_resources(scan_results):
    """Extract resources (packages, dependencies, files) from scan results."""
    resources = {
        'packages': [],
        'dependencies': [],
        'files': []
    }
    
    # Check if resources exist in scan results
    if 'resources' not in scan_results:
        return resources
    
    for resource in scan_results.get('resources', []):
        resource_type = resource.get('type')
        if resource_type == 'package':
            resources['packages'].append(resource)
        elif resource_type == 'dependency':
            resources['dependencies'].append(resource)
        elif resource_type == 'file':
            resources['files'].append(resource)
    
    return resources


def extract_vulnerabilities(scan_results):
    """Extract vulnerabilities from scan results."""
    vulnerabilities = []
    
    # Check if vulnerabilities exist in scan results
    if 'extra_data' in scan_results and 'vulnerabilities' in scan_results['extra_data']:
        vulnerabilities = scan_results['extra_data']['vulnerabilities']
    
    return vulnerabilities


def check_license_policy(resources, policy):
    """Check resources against license policy."""
    if not policy or 'license' not in policy:
        return True, []
    
    violations = []
    license_policy = policy['license']
    allowed_licenses = license_policy.get('allowed', [])
    prohibited_licenses = license_policy.get('prohibited', [])
    min_clarity_score = license_policy.get('minimum_clarity_score', 0)
    
    for resource in resources['files']:
        # Check if there are license detections in the file
        if 'detected_license_expression' not in resource or not resource['detected_license_expression']:
            continue
        
        # Get the detected license
        license_key = resource['detected_license_expression']
        
        # Check prohibited licenses
        if license_key in prohibited_licenses:
            violations.append({
                'type': 'prohibited_license',
                'license': license_key,
                'file_path': resource.get('path', ''),
                'message': f"Prohibited license '{license_key}' found in {resource.get('path', '')}"
            })
        
        # Check allowed licenses (if list is not empty)
        if allowed_licenses and license_key not in allowed_licenses:
            violations.append({
                'type': 'disallowed_license',
                'license': license_key,
                'file_path': resource.get('path', ''),
                'message': f"License '{license_key}' not in allowed list found in {resource.get('path', '')}"
            })
        
        # Check license clarity score from license detections if available
        if 'license_detections' in resource and resource['license_detections']:
            for detection in resource['license_detections']:
                if 'matches' in detection and detection['matches']:
                    for match in detection['matches']:
                        score = match.get('score', 0)
                        if score < min_clarity_score:
                            violations.append({
                                'type': 'low_clarity_score',
                                'license': license_key,
                                'score': score,
                                'file_path': resource.get('path', ''),
                                'message': f"License '{license_key}' has clarity score {score}, which is below minimum {min_clarity_score}"
                            })
    
    return len(violations) == 0, violations


def check_vulnerability_policy(vulnerabilities, policy):
    """Check vulnerabilities against policy."""
    if not policy or 'vulnerabilities' not in policy:
        return True, []
    
    violations = []
    vuln_policy = policy['vulnerabilities']
    max_severity = vuln_policy.get('maximum_severity', 'critical').lower()
    fail_on_unpatchable = vuln_policy.get('fail_on_unpatchable', False)
    
    # Map severity levels to numeric values for comparison
    severity_levels = {
        'none': 0,
        'low': 1,
        'medium': 2,
        'high': 3,
        'critical': 4
    }
    max_severity_level = severity_levels.get(max_severity, 4)
    
    for vuln in vulnerabilities:
        severity = vuln.get('severity', '').lower()
        severity_level = severity_levels.get(severity, 0)
        
        # Check severity level
        if severity_level > max_severity_level:
            violations.append({
                'type': 'high_severity_vulnerability',
                'vulnerability_id': vuln.get('vulnerability_id', ''),
                'severity': severity,
                'package': vuln.get('package', {}).get('purl', ''),
                'message': f"Vulnerability {vuln.get('vulnerability_id', '')} has severity '{severity}' which exceeds maximum allowed '{max_severity}'"
            })
        
        # Check for unpatchable vulnerabilities
        if fail_on_unpatchable and not vuln.get('is_patchable', True):
            violations.append({
                'type': 'unpatchable_vulnerability',
                'vulnerability_id': vuln.get('vulnerability_id', ''),
                'severity': severity,
                'package': vuln.get('package', {}).get('purl', ''),
                'message': f"Unpatchable vulnerability {vuln.get('vulnerability_id', '')} found in {vuln.get('package', {}).get('purl', '')}"
            })
    
    return len(violations) == 0, violations


def enhance_sbom(scan_results, output_dir, sbom_format):
    """Enhance existing SBOMs with additional vulnerability data."""
    if sbom_format.lower() == "false":
        return
    
    resources = extract_resources(scan_results)
    vulnerabilities = extract_vulnerabilities(scan_results)
    
    # Get paths to existing SBOM files
    output_path = Path(output_dir)
    spdx_path = None
    cyclonedx_path = None
    
    # Look for existing SBOM files
    for file_path in output_path.glob("*"):
        if file_path.name.endswith(".spdx.json") or file_path.name.endswith(".spdx"):
            spdx_path = file_path
        elif file_path.name.endswith(".cdx.json") or file_path.name.endswith(".cdx.xml"):
            cyclonedx_path = file_path
    
    # Enhance SBOMs based on format option
    formats_to_enhance = []
    if sbom_format.lower() == "both":
        formats_to_enhance = ["spdx", "cyclonedx"]
    elif sbom_format.lower() in ["spdx", "cyclonedx"]:
        formats_to_enhance = [sbom_format.lower()]
    
    for fmt in formats_to_enhance:
        if fmt == "spdx" and spdx_path:
            enhance_spdx_sbom(spdx_path, vulnerabilities)
        elif fmt == "cyclonedx" and cyclonedx_path:
            enhance_cyclonedx_sbom(cyclonedx_path, vulnerabilities)


def enhance_spdx_sbom(spdx_path, vulnerabilities):
    """Enhance SPDX SBOM with vulnerability data."""
    try:
        with open(spdx_path, 'r') as f:
            spdx_data = json.load(f)
        
        # Add vulnerability annotations to packages
        if 'packages' in spdx_data:
            for package in spdx_data['packages']:
                package_purl = package.get('externalRefs', [{}])[0].get('referenceLocator', '')
                
                # Find vulnerabilities for this package
                package_vulns = [v for v in vulnerabilities if v.get('package', {}).get('purl', '') == package_purl]
                
                if package_vulns:
                    # Add annotations for vulnerabilities
                    if 'annotations' not in package:
                        package['annotations'] = []
                    
                    for vuln in package_vulns:
                        package['annotations'].append({
                            'annotationType': 'SECURITY',
                            'annotator': 'Tool: ScanCode.io',
                            'comment': f"Vulnerability ID: {vuln.get('vulnerability_id', '')}, Severity: {vuln.get('severity', '')}"
                        })
        
        # Write enhanced SPDX
        with open(spdx_path, 'w') as f:
            json.dump(spdx_data, f, indent=2)
        
        print(f"Enhanced SPDX SBOM with vulnerability data: {spdx_path}")
    
    except Exception as e:
        print(f"Error enhancing SPDX SBOM: {e}")


def enhance_cyclonedx_sbom(cyclonedx_path, vulnerabilities):
    """Enhance CycloneDX SBOM with vulnerability data."""
    # Check if it's JSON or XML format
    is_json = str(cyclonedx_path).endswith('.json')
    
    try:
        if is_json:
            with open(cyclonedx_path, 'r') as f:
                cyclonedx_data = json.load(f)
            
            # Add vulnerabilities to components
            if 'components' in cyclonedx_data:
                for component in cyclonedx_data.get('components', []):
                    purl = component.get('purl', '')
                    
                    # Find vulnerabilities for this component
                    component_vulns = [v for v in vulnerabilities if v.get('package', {}).get('purl', '') == purl]
                    
                    if component_vulns:
                        # Add vulnerabilities section if it doesn't exist
                        if 'vulnerabilities' not in cyclonedx_data:
                            cyclonedx_data['vulnerabilities'] = []
                        
                        # Add each vulnerability
                        for vuln in component_vulns:
                            vulnerability = {
                                'id': vuln.get('vulnerability_id', ''),
                                'ratings': [
                                    {
                                        'severity': vuln.get('severity', '').upper(),
                                        'method': 'VulnerableCode'
                                    }
                                ],
                                'affects': [
                                    {
                                        'ref': purl
                                    }
                                ]
                            }
                            cyclonedx_data['vulnerabilities'].append(vulnerability)
            
            # Write enhanced CycloneDX
            with open(cyclonedx_path, 'w') as f:
                json.dump(cyclonedx_data, f, indent=2)
            
            print(f"Enhanced CycloneDX SBOM with vulnerability data: {cyclonedx_path}")
        else:
            # For XML format, we would need to use an XML parser
            print(f"XML CycloneDX enhancement not implemented yet: {cyclonedx_path}")
    
    except Exception as e:
        print(f"Error enhancing CycloneDX SBOM: {e}")


def generate_summary(resources, vulnerabilities, license_violations, vuln_violations):
    """Generate a summary of scan results and policy violations."""
    summary = {
        'resources': {
            'packages': len(resources['packages']),
            'dependencies': len(resources['dependencies']),
            'files': len(resources['files'])
        },
        'vulnerabilities': {
            'total': len(vulnerabilities),
            'by_severity': {}
        },
        'policy_violations': {
            'license': license_violations,
            'vulnerabilities': vuln_violations
        }
    }
    
    # Count vulnerabilities by severity
    for vuln in vulnerabilities:
        severity = vuln.get('severity', 'unknown').lower()
        if severity not in summary['vulnerabilities']['by_severity']:
            summary['vulnerabilities']['by_severity'][severity] = 0
        summary['vulnerabilities']['by_severity'][severity] += 1
    
    return summary


def main():
    """Main function."""
    args = parse_arguments()
    
    # Find the actual results file
    input_dir = os.path.dirname(args.input)
    results_files = [f for f in os.listdir(input_dir) if f.startswith("results-") and f.endswith(".json")]
    
    if not results_files:
        print(f"Error: No results file found in {input_dir}")
        sys.exit(1)
    
    # Use the most recent results file (should be only one in most cases)
    results_file = os.path.join(input_dir, sorted(results_files)[-1])
    print(f"Using results file: {results_file}")
    
    # Load scan results
    scan_results = load_scan_results(results_file)
    
    # Load policy configuration if provided
    policy = load_policy(args.policy) if args.policy else None
    
    # Extract resources and vulnerabilities
    resources = extract_resources(scan_results)
    vulnerabilities = extract_vulnerabilities(scan_results)
    
    # Check against policies
    license_check_passed, license_violations = check_license_policy(resources, policy)
    vuln_check_passed, vuln_violations = check_vulnerability_policy(vulnerabilities, policy)
    
    # Enhance SBOMs if requested
    if args.generate_sbom.lower() == "true":
        output_dir = os.path.dirname(results_file)
        enhance_sbom(scan_results, output_dir, args.sbom_format)
    
    # Generate summary
    summary = generate_summary(resources, vulnerabilities, license_violations, vuln_violations)
    
    # Write summary to output file
    summary_path = os.path.join(os.path.dirname(results_file), "scan-summary.json")
    with open(summary_path, 'w') as f:
        json.dump(summary, f, indent=2)
    
    # Print summary to console
    print("\n=== SCAN SUMMARY ===")
    print(f"Packages: {summary['resources']['packages']}")
    print(f"Dependencies: {summary['resources']['dependencies']}")
    print(f"Files: {summary['resources']['files']}")
    print(f"Vulnerabilities: {summary['vulnerabilities']['total']}")
    
    if summary['vulnerabilities']['by_severity']:
        print("Vulnerabilities by severity:")
        for severity, count in summary['vulnerabilities']['by_severity'].items():
            print(f"  {severity}: {count}")
    
    if license_violations:
        print("\nLicense policy violations:")
        for violation in license_violations:
            print(f"  {violation['message']}")
    
    if vuln_violations:
        print("\nVulnerability policy violations:")
        for violation in vuln_violations:
            print(f"  {violation['message']}")
    
    # Determine exit code based on policy checks and fail-on-findings flag
    policy_passed = license_check_passed and vuln_check_passed
    if args.fail_on_findings.lower() == "true" and not policy_passed:
        print("\nPolicy violations found. Failing the workflow.")
        sys.exit(1)
    else:
        sys.exit(0)


if __name__ == "__main__":
    main()
#!/usr/bin/env python3
import argparse
import json
import os
import sys
from pathlib import Path

def parse_args():
    parser = argparse.ArgumentParser(description='Process ScanCode.io results')
    parser.add_argument('--input', required=True, help='Path to ScanCode.io JSON output file')
    parser.add_argument('--policy', help='Path to policy configuration file')
    parser.add_argument('--generate-sbom', default='true', help='Generate comprehensive SBOM')
    parser.add_argument('--sbom-format', default='both', help='SBOM format (spdx, cyclonedx, or both)')
    parser.add_argument('--fail-on-findings', default='false', help='Fail workflow on policy violations')
    return parser.parse_args()

def load_scancode_results(json_path):
    with open(json_path, 'r') as f:
        return json.load(f)

def load_policy(policy_path):
    if not policy_path or not os.path.exists(policy_path):
        return None
    
    with open(policy_path, 'r') as f:
        return json.load(f)

def check_policy_violations(scan_results, policy):
    """Check scan results against policy rules"""
    if not policy:
        return False, []
    
    violations = []
    
    # Example: Check for license violations
    if 'license' in policy and 'resources' in scan_results:
        prohibited_licenses = policy.get('license', {}).get('prohibited', [])
        for resource in scan_results.get('resources', []):
            if 'license_detections' in resource:
                for detection in resource.get('license_detections', []):
                    license_expression = detection.get('license_expression')
                    if license_expression in prohibited_licenses:
                        violations.append(f"Prohibited license '{license_expression}' found in {resource.get('path')}")
    
    # Example: Check for vulnerability violations
    if 'vulnerabilities' in policy and 'vulnerabilities' in scan_results:
        max_severity = policy.get('vulnerabilities', {}).get('maximum_severity')
        severity_levels = {'none': 0, 'low': 1, 'medium': 2, 'high': 3, 'critical': 4}
        max_severity_level = severity_levels.get(max_severity, 4) if max_severity else 4
        
        for vuln in scan_results.get('vulnerabilities', []):
            severity = vuln.get('severity', 'unknown').lower()
            severity_level = severity_levels.get(severity, 0)
            
            if severity_level > max_severity_level:
                violations.append(f"Vulnerability {vuln.get('vulnerability_id')} has severity '{severity}' which exceeds allowed maximum '{max_severity}'")
    
    return len(violations) > 0, violations

def generate_enhanced_sbom(scan_results, output_dir, format):
    """Generate enhanced SBOM with vulnerability data"""
    # This is a simplified placeholder for the actual implementation
    # You would extend this to properly format and integrate vulnerability data
    
    if format.lower() in ['spdx', 'both']:
        sbom_path = os.path.join(output_dir, 'enhanced-sbom.spdx.json')
        with open(sbom_path, 'w') as f:
            # Create enhanced SPDX SBOM
            # This would involve formatting scan_results in SPDX format
            json.dump(scan_results, f, indent=2)
            print(f"Enhanced SPDX SBOM written to {sbom_path}")
    
    if format.lower() in ['cyclonedx', 'both']:
        sbom_path = os.path.join(output_dir, 'enhanced-sbom.cyclonedx.json')
        with open(sbom_path, 'w') as f:
            # Create enhanced CycloneDX SBOM
            # This would involve formatting scan_results in CycloneDX format
            json.dump(scan_results, f, indent=2)
            print(f"Enhanced CycloneDX SBOM written to {sbom_path}")

def main():
    args = parse_args()
    
    # Load scan results
    scan_results = load_scancode_results(args.input)
    output_dir = str(Path(args.input).parent)
    
    # Generate enhanced SBOM if requested
    if args.generate_sbom.lower() == 'true':
        generate_enhanced_sbom(scan_results, output_dir, args.sbom_format)
    
    # Check for policy violations if a policy file was provided
    if args.policy:
        policy = load_policy(args.policy)
        has_violations, violations = check_policy_violations(scan_results, policy)
        
        # Output violations
        if has_violations:
            print("\n⚠️ Policy violations detected:")
            for violation in violations:
                print(f"  - {violation}")
            
            # Set exit code to fail the workflow if configured
            if args.fail_on_findings.lower() == 'true':
                print("\n❌ Workflow failed due to policy violations")
                sys.exit(1)
            else:
                print("\n⚠️ Policy violations found, but continuing workflow as fail-on-findings is disabled")
        else:
            print("\n✅ No policy violations found")
    
    print("\n✅ Processing completed successfully")
    return 0

if __name__ == "__main__":
    sys.exit(main())
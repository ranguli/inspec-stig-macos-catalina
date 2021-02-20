# frozen_string_literal: true

control 'V-225152' do
  impact 0.5
  title "The macOS system must audit the enforcement actions used to restrict
         access associated with changes to the system."
  desc  "By auditing access restriction enforcement, changes to application
        and OS configuration files can be audited. Without auditing the
        enforcement of access restrictions, it will be difficult to identify
        attempted attacks and an audit trail will not be available for forensic
        investigation. Enforcement actions are the methods or mechanisms used
        to prevent unauthorized changes to configuration settings. Enforcement
        action methods may be as simple as denying access to a file based on
        the application of file permissions (access restriction). Audit items
        may consist of lists of actions blocked by access restrictions or
        changes identified after the fact. Without generating audit records
        that are specific to the security and mission needs of the
        organization, it would be difficult to establish, correlate, and
        investigate the events relating to an incident or identify those
        responsible for one. Audit records can be generated from various
        components within the information system (e.g., module or policy
        filter)."
  tag stig_id: 'AOSX-15-001020'
  tag severity: 'medium'

  describe command('/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control') do
    its('stdout.strip') { should match(/fm/) }
    its('stdout.strip') { should match(/-fr/) }
    its('stdout.strip') { should match(/-fw/) }
    its('stdout.strip') { should match(/-fd/) }
  end
end

# frozen_string_literal: true

control 'V-225155' do
  impact 0.5
  title "The macOS system must provide an immediate real-time alert to the
        System Administrator (SA) and Information System Security Officer
        (ISSO), at a minimum, of all audit failure events requiring real-time
        alerts."
  desc  "The audit service should be configured to immediately print messages
        to the console or email administrator users when an auditing failure
        occurs. It is critical for the appropriate personnel to be aware if a
        system is at risk of failing to process audit logs as required. Without
        a real-time alert, security personnel may be unaware of an impending
        failure of the audit capability and system operation may be adversely
        affected."
  tag stig_id: 'AOSX-15-001031'
  tag severity: 'medium'

  describe command('/usr/bin/sudo /usr/bin/grep logger /etc/security/audit_warn') do
    its('stdout.strip') { should match(/-s/) }
  end
end

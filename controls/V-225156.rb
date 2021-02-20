# frozen_string_literal: true

control 'V-225156' do
  impact 0.5
  title "The macOS system must generate audit records for DoD-defined events
        such as successful/unsuccessful logon attempts, successful/unsuccessful
        direct access attempts, starting and ending time for user access, and
        concurrent logons to the same account from different sources."
  desc  "Without generating audit records that are specific to the security and
        mission needs of the organization, it would be difficult to establish,
        correlate, and investigate the events relating to an incident or
        identify those responsible for one. Audit records can be generated from
        various components within the information system (e.g., module or
        policy filter)"
  tag stig_id: 'AOSX-15-001044'
  tag severity: 'medium'

  describe command('/usr/bin/sudo /usr/bin/grep ^flags /etc/security/audit_control') do
    its('stdout.strip') { should match(/aa/) }
  end
end

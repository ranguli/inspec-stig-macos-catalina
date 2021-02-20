# frozen_string_literal: true

control 'V-225153' do
  impact 0.5
  title "The macOS system must allocate audit record storage capacity to store
        at least one week\'s worth of audit records when audit records are not
        immediately sent to a central audit record storage facility."
  desc  "The audit service must be configured to require that records are kept
        for seven days or longer before deletion when there is no central audit
        record storage facility. When \"expire-after\" is set to \"7d\", the audit
        service will not delete audit logs until the log data is at least seven
        days old."
  tag stig_id: 'AOSX-15-001029'
  tag severity: 'medium'

  describe command('/usr/bin/sudo /usr/bin/grep ^expire-after /etc/security/audit_control') do
    its('stdout.strip') { should eq 'expire-after:7D' }
  end
end

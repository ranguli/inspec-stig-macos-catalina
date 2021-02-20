# frozen_string_literal: true

control 'V-234700' do
  impact 0.5
  title "The macOS system must be configured to disable SMB File Sharing unless
        it is required."
  desc  "File Sharing is usually non-essential and must be disabled if not
        required. Enabling any service increases the attack surface for an
        intruder. By disabling unnecessary services, the attack surface is
        minimized."
  tag stig_id: 'AOSX-15-002001'
  tag severity: 'medium'

  cmd = 'security authorizationdb read system.preferences | grep -A1 shared'
  describe command(cmd) do
    its('stdout.strip') { should match(/false/i) }
  end
end

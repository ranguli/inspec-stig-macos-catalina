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

  cmd = 'security authorizationdb read system.preferences > /tmp/system_preferences.plist'

  describe command(cmd) do
  end

  describe plist('/tmp/system_preferences.plist') do
    its('shared') {should eq false }
  end
end

# frozen_string_literal: true

control 'V-225159' do
  impact 0.5
  title "The macOS system must be configured to disable SMB File Sharing unless
        it is required."
  desc  "File Sharing is usually non-essential and must be disabled if not
        required. Enabling any service increases the attack surface for an
        intruder. By disabling unnecessary services, the attack surface is
        minimized."
  tag stig_id: 'AOSX-15-002001'
  tag severity: 'medium'

  describe command('launchctl print-disabled system | grep com.apple.smbd') do
    its('stdout.strip') { should eq '"com.apple.smbd" => true'}
  end
end

# frozen_string_literal: true

control 'V-225154' do
  impact 0.5
  title "The macOS system must provide an immediate warning to the System
        Administrator (SA) and Information System Security Officer (ISSO)
        (at a minimum) when allocated audit record storage volume reaches
        75 percent of repository maximum audit record storage capacity."
  desc  "The audit service must be configured to require a minimum percentage
        of free disk space in order to run. This ensures that audit will notify
        the administrator that action is required to free up more disk space
        for audit logs. When \"minfree\" is set to 25 percent, security personnel
        are notified immediately when the storage volume is 75 percent full and
        are able to plan for audit record storage capacity expansion."
  tag stig_id: 'AOSX-15-001030'
  tag severity: 'medium'

  describe command('/usr/bin/sudo /usr/bin/grep ^minfree /etc/security/audit_control') do
    its('stdout.strip') { should eq "minfree:25" }
  end
end

# frozen_string_literal: true

control 'V-225218' do
  impact 1.0
  tag severity: 'high'
  title "The macOS system must be configured with the sudoers file configured
        to authenticate users on a per -tty basis."
  desc  "The \"sudo\" command must be configured to prompt for the
        administrator\'s password at least once in each newly opened Terminal
        window or remote logon session, as this prevents a malicious user from
        taking advantage of an unlocked computer or an abandoned logon session
        to bypass the normal password prompt requirement. Without the
        \"tty_tickets\" option, all open local and remote logon sessions would
        be authenticated to use sudo without a password for the duration of the
        configured password timeout window."
  tag stig_id: 'AOSX-15-004021'

  describe command('sudo grep tty_tickets /etc/sudoers') do
    its('stdout.strip') { should eq 'Defaults    tty_tickets' }
  end
end

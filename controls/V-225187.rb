# frozen_string_literal: true

control 'V-225187' do
  impact 1.0
  title 'The macOS system must be configured to disable the tftp service'
  desc  "The \"tftp\" service must be disabled as it sends all data in a
        clear-text form that can be easily intercepted and read. The data
        needs to be protected at all times during transmission, and encryption
        is the standard method for protecting data in transit. If the data is
        not encrypted during transmission, it can be plainly read (i.e., clear
        text) and easily compromised. Disabling ftp is one way to mitigate this
        risk. Administrators should be instructed to use an alternate service
        for data transmission that uses encryption, such as SFTP. Additionally,
        the \"tftp\" service uses UDP which is not secure."
  tag stig_id: 'AOSX-15-002038'
  tag severity: 'high'

  describe command('launchctl print-disabled system | grep tftpd') do
    its('stdout.strip') { should eq '"com.apple.tftpd" => true' }
  end
end

control 'V-225187' do
  impact 'high'
  title 'The macOS system must be configured to disable the tftp service.'
  desc 'The "tftp" service must be disabled as it sends all data in a clear-text form that can be easily intercepted and read. The data needs to be protected at all times during transmission, and encryption is the standard method for protecting data in transit. If the data is not encrypted during transmission, it can be plainly read (i.e., clear text) and easily compromised. Disabling ftp is one way to mitigate this risk. Administrators should be instructed to use an alternate service for data transmission that uses encryption, such as SFTP. Additionally, the "tftp" service uses UDP which is not secure.'
  tag disa: 'AOSX-15-002038'
  ref 'https://www.stigviewer.com/stig/apple_os_x_10.15_catalina/2020-12-11/finding/V-225187'

  describe command('launchctl print-disabled system | grep tftpd') do
    its('stdout.strip') { should eq '"com.apple.tftpd" => true' }
  end

end

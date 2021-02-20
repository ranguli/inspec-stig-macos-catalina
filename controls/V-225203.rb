control 'V-225203' do
  impact 'high'
  title 'The macOS system must use an approved antivirus program.'
  desc 'An approved antivirus product must be installed and configured to run. Malicious software can establish a base on individual desktops and servers. Employing an automated mechanism to detect this type of software will aid in elimination of the software from the operating system.'
  tag disa: 'AOSX-15-002070'
  ref 'https://www.stigviewer.com/stig/apple_os_x_10.15_catalina/2020-12-11/finding/V-225203'

  describe launchd_service(input('antivirus_daemon')) do
    it { should be_installed }
    it { should be_enabled }
    it { should be_running }
  end

end

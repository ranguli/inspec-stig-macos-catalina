control 'V-225181' do
  impact 'high'
  title 'The macOS system must be configured to disable the system preference pane for iCloud.'
  desc 'It is detrimental for operating systems to provide, or install by default, functionality exceeding requirements or mission objectives. These unnecessary capabilities or services are often overlooked and therefore may remain unsecured. They increase the risk to the platform by providing additional attack vectors. Operating systems are capable of providing a wide variety of functions and services. Some of the functions and services, provided by default, may not be necessary to support essential organizational operations (e.g., key missions, functions). Examples of non-essential capabilities include but are not limited to games, software packages, tools, and demonstration software not related to requirements or providing a wide array of functionality not required for every mission but that cannot be disabled. The iCloud System Preference Pane must be disabled.'
  tag disa: 'AOSX-15-002031'
  ref 'https://www.stigviewer.com/stig/apple_os_x_10.15_catalina/2020-12-11/finding/V-225181'

  describe command('/usr/sbin/system_profiler SPConfigurationProfileDataType | /usr/bin/grep -A 6 DisabledPreferencePanes | grep AppleIDPrefPane') do
    its('stdout.strip') { should eq 'com.apple.preferences.AppleIDPrefPane'}
  end
end

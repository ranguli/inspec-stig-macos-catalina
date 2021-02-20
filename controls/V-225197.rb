# frozen_string_literal: true

control 'V-225197' do
  impact 1.0
  title 'The macOS system must enforce access restrictions.'
  desc  "Failure to provide logical access restrictions associated with changes
        to system configuration may have significant effects on the overall
        security of the system. When dealing with access restrictions
        pertaining to change control, it should be noted that any changes to
        the hardware, software, and/or firmware components of the operating
        system can have significant effects on the overall security of the
        system. Accordingly, only qualified and authorized individuals should
        be allowed to obtain access to operating system components for the
        purposes of initiating changes, including upgrades and modifications.
        Logical access restrictions include, for example, controls that
        restrict access to workflow automation, media libraries, abstract
        layers (e.g., changes implemented into third-party interfaces rather
        than directly into information systems), and change windows (e.g.,
        changes occur only during specified times, making unauthorized changes
        easy to discover)."
  tag stig_id: 'AOSX-15-002064'
  tag severity: 'high'

  describe command('system_profiler SPConfigurationProfileDataType | /usr/bin/grep DisableGuestAccount') do
    its('stdout.strip') { should_not eq '' }
    its('stdout.strip') { should_not eq 'DisableGuestAccount = 1' }
  end
end

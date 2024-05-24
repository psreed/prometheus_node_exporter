# @summary 
#  Puppet module to install and configure Prometheus Node Exporter
#
# @example
#   include prometheus_node_exporter
# @example
#   class { 'prometheus_node_exporter':
#     basic_auth_enabled => true,
#   }
#
# @param basic_auth_enabled
#   Determines if basic web authentication is used
# @param basic_auth_hash_salt
#   Sets the hash salt for basic web based authentication. Exactly 22 characters, no symbols
# @param basic_auth_hash_strength
#   Strength of the hash, number represented as string between 4 and 31 inclusive
# @param basic_auth_password
#   Sets the password for basic web based authentication
# @param basic_auth_username
#   Sets the username for basic web based authentication
# @param binary_symlink
#   Location to symlink binary for execution
# @param extra_configuration_options
#   A hash of additional configuration items to add to the service start command.  
#   Example:  
#   {  
#     '--collector.textfile.directory' => '/var/lib/node_exporter/textfile/'  
#   }  
# @param manage_installation
#   Manage the installation from tarball sourc
# @param manage_service_user
#   Manage the local user to run the service as
# @param manage_selinux_requirements
#   Manage SE Linux to allow node exporter to run
# @param manage_systemd_service
#   Manage the configuration of the systemd service definition
# @param service_enabled
#   Set if systemd service is enabled at boot time
# @param service_ensure
#   Value for systemd service configuration: running, stopped, etc.
# @param service_group
#   The local group to run the node_exporter service
# @param service_username
#   The local username to run the node_exporter service
# @param source_archive_base
#   Base location for source archive
# @param systemd_service_file
#   File location for systemd service definition
# @param systemd_service_name
#   Service name for systemd service definition
# @param target_folder_location
#   Location on filesystem to for archive extraction & program location
# @param tls_enabled
#   Determines whether to use TLS/SSL for web connections
# @param tls_certificate_file
#   Location on filesystem of public certificate file for TLS communications
# @param tls_private_key_file
#   Location on filesystem of private key file for TLS communications
# @param tls_use_puppet_certificates
#   Determines whether to use the Puppet agent certificates for TLS
#   - If set true, will use Puppet agent certificate files for TLS
#   - If set false, will use $tls_certificate_file and $tls_private_key_file
# @param version
#   Version of Prometheus Node Exporter to download, install and configure
# @param web_configuration_folder
#   Filesystem folder location for Node Exporter web configuration
# @param web_configuration_file
#   Filename for the web configuration file in the web_configuration_folder
# @param web_listen_address
#   Address:port combination to bind on for web listener
#
class prometheus_node_exporter (
  Boolean           $basic_auth_enabled          = true,
  Sensitive[String] $basic_auth_hash_salt        = Sensitive('0123456789AbCdEfGhIjKl'),
  String            $basic_auth_hash_strength    = '10',
  Sensitive[String] $basic_auth_password         = Sensitive('<password>'),
  String            $basic_auth_username         = 'prometheus',
  String            $binary_symlink              = '/usr/local/bin/node_exporter',
  Hash              $extra_configuration_options = {},
  Boolean           $manage_installation         = true,
  Boolean           $manage_selinux_requirements = true,
  Boolean           $manage_service_user         = true,
  Boolean           $manage_systemd_service      = true,
  Boolean           $service_enabled             = true,
  String            $service_ensure              = running,
  String            $service_group               = 'node_exporter',
  String            $service_username            = 'node_exporter',
  String            $source_archive_base         = 'https://github.com/prometheus/node_exporter/releases/download',
  String            $systemd_service_file        = '/etc/systemd/system/node_exporter.service',
  String            $systemd_service_name        = 'node_exporter',
  String            $target_folder_location      = '/opt',
  Boolean           $tls_enabled                 = true,
  String            $tls_certificate_file        = '/etc/prometheus_node_exporter/tlsCertificate.crt',
  String            $tls_private_key_file        = '/etc/prometheus_node_exporter/tlsCertificate.key',
  Boolean           $tls_use_puppet_certificates = true,
  String            $version                     = '1.8.1',
  String            $web_configuration_folder    = '/etc/prometheus_node_exporter',
  String            $web_configuration_file      = 'configuration.yml',
  String            $web_listen_address          = ':9100',
) {
  ##
  ## Classification check for valid OS, setup variables & SE Linux contexts
  ##
  # OS kernel check
  if downcase($facts['kernel']) != 'linux' and downcase($facts['kernel']) != 'darwin' {
    fail('The Prometheus Node Exporter only supports Darwin and Linux kernels. It cannot currently be installed on this system.')
  }

  # Resovle variables
  $architecture = $facts['os']['architecture'] ? {
    'x86_64'  => 'amd64',
    'aarch64' => 'arm64',
    default   => 'amd64',
  }
  $basename = "node_exporter-${version}.${downcase($facts['kernel'])}-${architecture}"
  $configuration = "${web_configuration_folder}/${web_configuration_file}"
  $basic_auth_password_hashed = Sensitive(pw_hash($basic_auth_password, 'bcrypt-a', "${basic_auth_hash_strength}$${basic_auth_hash_salt.unwrap()}")) #lint:ignore:140chars

  # Define SE Linux contexts (if managed)
  if $manage_selinux_requirements {
    $selinux_binary_file_params = {
      selrange => 's0',
      selrole  => 'object_r',
      seluser  => 'system_u',
      seltype  => 'bin_t',
    }
    $selinux_config_file_params = {
      selrange => 's0',
      selrole  => 'object_r',
      seluser  => 'system_u',
      seltype  => 'system_conf_t',
    }
  }

  ##
  ## Install Prometheus Node Exporter binary from realease archive
  ##
  if $manage_installation {
    # Extract Archive
    archive { "${target_folder_location}/${basename}.tar.gz":
      ensure       => present,
      extract      => true,
      extract_path => $target_folder_location,
      source       => "${source_archive_base}/v${version}/${basename}.tar.gz",
      creates      => "${target_folder_location}/${basename}",
      cleanup      => true,
    }

    # Set binary file owner, permissions and selinux context (if applicable)
    ensure_resource('file',"${target_folder_location}/${basename}/node_exporter", $selinux_binary_file_params + {
        ensure => file,
        owner => $service_username,
        group => $service_group,
        mode => '0750',
        require => Archive["${target_folder_location}/${basename}.tar.gz"],
        before  => File[$binary_symlink],
    })

    # Create symlink in /usr/local/bin
    ensure_resource('file',$binary_symlink, $selinux_binary_file_params + {
        ensure => link,
        owner => $service_username,
        group => $service_group,
        mode => '0640',
        target  => "${target_folder_location}/${basename}/node_exporter",
        require => Archive["${target_folder_location}/${basename}.tar.gz"],
    })
  }

  ##
  ## Manage systemd service definition
  ##
  if $manage_systemd_service {
    # systemd service definition file
    file { $systemd_service_file:
      ensure  => file,
      content => epp('prometheus_node_exporter/node_exporter.service.epp', {
          binary_symlink              => $binary_symlink,
          configuration               => $configuration,
          extra_configuration_options => $extra_configuration_options,
          service_username            => $service_username,
          service_group               => $service_group,
          web_listen_address          => $web_listen_address,
      }),
    }
    # set requirement for user resource to exist first (if managed)
    if $manage_service_user {
      $service_user_params = {
        require => User[$service_username],
      }
    }
    # Manage the service
    ensure_resource('service', $systemd_service_name, $service_user_params + {
        ensure    => $service_ensure,
        enable    => $service_enabled,
        require   => File[$systemd_service_file],
        subscribe => [File[$configuration], File[$systemd_service_file]],
    })
  }

  ##
  ## Manage service user
  ##
  if $manage_service_user {
    group { $service_group: ensure => present, }
    $groups = $tls_use_puppet_certificates ? { true => [$service_group,'root'], false => [$service_group] }
    user { $service_username:
      ensure  => present,
      shell   => '/bin/false',
      groups  => $groups,
      require => Group[$service_group],
      before  => [File[$web_configuration_folder],File[$configuration]],
    }
  }

  ##
  ## Manage web configuration
  ##
  # Manage the web configuration folder
  ensure_resource('file',$web_configuration_folder, $selinux_config_file_params + {
      ensure => directory,
      owner  => $service_username,
      group  => $service_group,
      mode    => '0750',
  })
  # Manage the web configuration file
  if $tls_use_puppet_certificates {
    $tls_cert    = "${facts['puppet_sslpaths']['certdir']['path']}/${facts['clientcert']}.pem"
    $tls_privkey = "${facts['puppet_sslpaths']['privatekeydir']['path']}/${facts['clientcert']}.pem"
  } else {
    $tls_cert    = $tls_certificate_file
    $tls_privkey = $tls_private_key_file
  }
  ensure_resource('file',$configuration, $selinux_config_file_params + {
      owner   => $service_username,
      group   => $service_group,
      mode    => '0640',
      content => epp('prometheus_node_exporter/configuration.yml.epp', {
          basic_auth_enabled         => $basic_auth_enabled,
          basic_auth_password_hashed => $basic_auth_password_hashed,
          basic_auth_username        => $basic_auth_username,
          tls_enabled                => $tls_enabled,
          tls_certificate_file       => $tls_cert,
          tls_private_key_file       => $tls_privkey,
      }),
      require => File[$web_configuration_folder],
  })
}

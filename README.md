# prometheus_node_exporter

Puppet module to install and configure Prometheus Node Exporter

See `REFERENCE.md` for parameter references.

## `extra_confguration_options` and handling parameters with an optional `[no-]` prefix

`--web.config.file` and `--web.listen-address` have explicit module parameters and should not be included with `extra_configuration_options`.

Other parameters supported by the `node_exporter` binary can be added using the `extra_configuration_options` module parameter.

Parameters with an optional `[no-]` prefix flag (`--[no-]collector.zfs`, for exmpale) are supplied to the module via `true`/`false` values.

For example:

`--no-collector.zfs` would be represented using `'--collector.zfs' => false` in Puppet DSL or `'--collector.xfs': false` in Hiera YAML.

`--collector.zfs` would be represented using `'--collector.zfs' => true` in Puppet DSL or `'--collector.xfs': true` in Hiera YAML.

## Hiera:

All parameters are supported for automatic lookup from Hiera.

Example:
```
prometheus_node_exporter::basic_auth_enabled: true
prometheus_node_exporter::basic_auth_hash_salt: DontUseThisHashSalt123
prometheus_node_exporter::basic_auth_password: DontUseThisPassword
prometheus_node_exporter::tls_use_puppet_certificates: true
prometheus_node_exporter::extra_configuration_options:
  - '--collector.textfile.directory': /var/lib/node_exporter/textfile
    '--collector.xfs': false
    '--collector.zfs': false
    '--log.level': debug
```


## Contributing

Pull requests from forks are reviewed and accepted as time allows.
Please use the associated Issues section in Github to report any issues to be corrected.

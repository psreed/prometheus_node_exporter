# Function to hash a password for prometheus node exporter
Puppet::Functions.create_function(:'prometheus_node_exporter::password_hash') do
  dispatch :func do
    required_param 'String', :password
    return_type 'String'
  end
  def func(password)
    BCrypt::Password.create(password)
  end
end

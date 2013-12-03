require 'omniauth/strategies/oauth'
require 'oauth/signature/plaintext'

module OmniAuth
  module Strategies
    class Magento < OmniAuth::Strategies::OAuth
      #args [:consumer_key, :consumer_secret, :site_id]
      
      option :client_options, {
        :access_token_path  => 'http://localhost:8888/magento/oauth/token',
        :authorize_path     => 'http://localhost:8888/magento/oauth/authorize',
        :request_token_path => 'http://localhost:8888/magento/oauth/initiate',
        :signature_method   => 'PLAINTEXT',
      }
    end
  end
end

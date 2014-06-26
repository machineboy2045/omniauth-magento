require 'omniauth/strategies/oauth'
require 'multi_json'
require 'digest'

module OmniAuth
  module Strategies
    class Magento < OmniAuth::Strategies::OAuth
      option :name, "magento"

      option :client_options, {
        :request_token_path => "/oauth/initiate",          
        :authorize_path     => "/oauth/authorize",          
        :access_token_path  => "/oauth/token"
      }
            
      # when colling Customer (not Admin) API, Magento returns user credentials for logged in Magento user
      # these credentials can then be used to create a new user in the Rails app
      # won't work with Admin API since /customers will return all customers

      uid do
        if not options.client_options.authorize_path == "/admin/oauth_authorize"
          raw_info.keys.first.to_i
        else
          Digest::SHA256.digest options.client_options.site
        end
      end      

      # set additional info
      info do
        if not options.client_options.authorize_path == "/admin/oauth_authorize"        
          {
            'first_name' => raw_info.values.first["firstname"],
            'last_name' => raw_info.values.first["lastname"],
            'email' => raw_info.values.first["email"]            
          }
        else
          {}
        end
      end

      # get info about current user
      def raw_info
        if not options.client_options.authorize_path == "/admin/oauth_authorize"        
          @raw_info ||= MultiJson.decode(access_token.get('/api/rest/customers').body)
        end
      end              
    end
  end
end

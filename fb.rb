require 'base64'
require 'hmac'
require 'hmac-sha2'
require 'httparty'

class FB
    include HTTParty

    @app_id = ""
    @facebook_secret = ""
    @redirect_uri = ""
    @token_uri = "https://graph.facebook.com/oauth/access_token"
    @graph_uri = "https://graph.facebook.com/me"

    def self.user_info(code)
        @code = code
        @result = get(@token_uri, :query => {
            :client_id => @app_id,
            :client_secret => @facebook_secret,
            :redirect_uri => @redirect_uri,
            :code => @code
        })
        @access_token = /access_token=([^&]+)/.match(@result.to_s)[1]
        graph = get(@graph_uri, :query => {:access_token => @access_token})
    end

    def self.base64_url_decode(str)
      str += '=' * (4 - str.length.modulo(4))
      Base64.decode64(str.gsub("-", "+").gsub("_", "/"))
    end

    def self.valid_facebook_signature?(signed_request)
      signature, encoded_data = signed_request.split(".")
      expected_signature = base64_url_decode(signature)
      computed_signature = HMAC::SHA256.digest(@facebook_secret, encoded_data)
      return expected_signature == computed_signature
    end

    def self.signed_request(signed_request)
        if (valid_facebook_signature?(signed_request))
            signature, encoded_data = signed_request.split(".")
            return base64_url_decode(encoded_data)
        else
            throw "Invalid signature!"
        end
    end
end

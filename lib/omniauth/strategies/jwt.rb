require 'omniauth'
require 'jwt'

module OmniAuth
  module Strategies
    class JWT
      class ClaimInvalid < StandardError; end

      include OmniAuth::Strategy

      args [:secret]

      option :secret, nil
      option :algorithm, 'HS256'
      option :uid_claim, 'email'
      option :required_claims, %w(name email)
      option :info_map, {"name" => "name", "email" => "email"}
      option :auth_url, nil
      option :valid_within, nil

      def request_phase
        redirect options.auth_url
      end

      def decoded
        unless @decoded
          @decoded, _ = ::JWT.decode(request.params['jwt'], secret, options.algorithm)
        end

        (options.required_claims || []).each do |field|
          raise ClaimInvalid.new("Missing required '#{field}' claim.") if !@decoded.key?(field.to_s)
        end
        raise ClaimInvalid.new("Missing required 'iat' claim.") if options.valid_within && !@decoded["iat"]
        raise ClaimInvalid.new("'iat' timestamp claim is too skewed from present.") if options.valid_within && (Time.now.to_i - @decoded["iat"]).abs > options.valid_within
        @decoded
      end

      def callback_phase
        super
      rescue ClaimInvalid => e
        fail! :claim_invalid, e
      end

      uid do
        if options.uid_claim.is_a?(String)
          decoded[options.uid_claim]
        else
          uid_lookup.uid(decoded)
        end
      end

      extra do
        {:raw_info => decoded}
      end

      info do
        options.info_map.inject({}) do |h,(k,v)|
          h[k.to_s] = decoded[v.to_s]
          h
        end
      end

      private

      def secret
        if options.secret.is_a?(String)
          options.secret
        elsif options.secret.is_a?(Hash)
          issuer_specific_secret
        else
          secret_lookup.secret
        end
      end

      def secret_lookup
        @secret_lookup ||= options.secret.new(request)
      end

      def uid_lookup
        @uid_lookup ||= options.uid_claim.new(request)
      end

      def issuer_specific_secret
        unverified_token = ::JWT.decode(request.params['jwt'], nil, false)[0]
        iss = unverified_token['iss']
        options.secret[iss]
      end
    end

    class Jwt < JWT; end
  end
end

require 'spec_helper'
require 'multi_json'

class TestLookup
  def initialize(request)
    @request = request
  end

  def secret
    "test_secret"
  end

  def uid(decoded)
    "foo"
  end
end

describe OmniAuth::Strategies::JWT do
  let(:response_json){ MultiJson.load(last_response.body) }
  let(:args){ ['imasecret', {auth_url: 'http://example.com/login'}] }

  let(:app){
    the_args = args
    Rack::Builder.new do |b|
      b.use Rack::Session::Cookie, secret: 'sekrit'
      b.use OmniAuth::Strategies::JWT, *the_args
      b.run lambda{|env| [200, {}, [(env['omniauth.auth'] || {}).to_json]]}
    end
  }

  context "when lookup class is defined" do
    let(:args) { [TestLookup, {:uid_claim => TestLookup}] }

    it "uses the provided class to lookup the key" do
      encoded = JWT.encode({name: 'Bob', email: 'steve@example.com'}, "test_secret")
      get '/auth/jwt/callback?jwt=' + encoded
      expect(response_json["info"]["email"]).to eq("steve@example.com")
    end

    it "provides a UID for the signatory" do
      encoded = JWT.encode({name: 'Bob', email: 'steve@example.com'}, "test_secret")
      get '/auth/jwt/callback?jwt=' + encoded
      expect(response_json["uid"]).to eq('foo')
    end
  end

  context 'request phase' do
    it 'should redirect to the configured login url' do
      get '/auth/jwt'
      expect(last_response.status).to eq(302)
      expect(last_response.headers['Location']).to eq('http://example.com/login')
    end
  end

  context 'callback phase' do
    it 'should decode the response' do
      encoded = JWT.encode({name: 'Bob', email: 'steve@example.com'}, 'imasecret')
      get '/auth/jwt/callback?jwt=' + encoded
      expect(response_json["info"]["email"]).to eq("steve@example.com")
    end

    it 'should not work without required fields' do
      encoded = JWT.encode({name: 'Steve'}, 'imasecret')
      get '/auth/jwt/callback?jwt=' + encoded
      expect(last_response.status).to eq(302)
    end

    it 'should assign the uid' do
      encoded = JWT.encode({name: 'Steve', email: 'dude@awesome.com'}, 'imasecret')
      get '/auth/jwt/callback?jwt=' + encoded
      expect(response_json["uid"]).to eq('dude@awesome.com')
    end

    context 'with a :valid_within option set' do
      let(:args){ ['imasecret', {auth_url: 'http://example.com/login', valid_within: 300}] }

      it 'should work if the iat key is within the time window' do
        encoded = JWT.encode({name: 'Ted', email: 'ted@example.com', iat: Time.now.to_i}, 'imasecret')
        get '/auth/jwt/callback?jwt=' + encoded
        expect(last_response.status).to eq(200)
      end

      it 'should not work if the iat key is outside the time window' do
        encoded = JWT.encode({name: 'Ted', email: 'ted@example.com', iat: Time.now.to_i + 500}, 'imasecret')
        get '/auth/jwt/callback?jwt=' + encoded
        expect(last_response.status).to eq(302)
      end

      it 'should not work if the iat key is missing' do
        encoded = JWT.encode({name: 'Ted', email: 'ted@example.com'}, 'imasecret')
        get '/auth/jwt/callback?jwt=' + encoded
        expect(last_response.status).to eq(302)
      end
    end

    describe 'secret' do
      context 'multiple issuers' do
        let(:args) { [{ issuer_1: 'secret_1', issuer_2: 'secret_2' }, {auth_url: 'http://example.com/login'}] }

        it 'should assign the uid' do
          encoded = JWT.encode({name: 'Steve', email: 'dude@awesome.com', iss: 'issuer_1'}, 'secret_1')
          get '/auth/jwt/callback?jwt=' + encoded
          expect(response_json["uid"]).to eq('dude@awesome.com')
        end
      end
    end
  end
end

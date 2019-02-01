class ApplicationController < ActionController::Base
  # Prevent CSRF attacks by raising an exception.
  # For APIs, you may want to use :null_session instead.
  protect_from_forgery with: :exception

  # authentication before all
  before_action :authenticate_user

  private

    # redirect the user if they have not already logged in
    def authenticate_user
      client_id = ENV['FOURSQUARE_CLIENT_ID']
      redirect_uri = CGI.escape("http://localhost:3000/auth")
      foursquare_url = "https://foursquare.com/oauth2/authenticate?client_id=#{client_id}&response_type=code&redirect_uri=#{redirect_uri}"
      redirect_to foursquare_url unless logged_in?
    end

    # is the user already logged in to foursquare?
    def logged_in?
      !!session[:token]
    end

end

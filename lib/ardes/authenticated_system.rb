require 'base64'

module Ardes#:nodoc:
  # adapted from technoweenies standard.
  # This auth system allows for recognition based on cookie, and a few other
  # niceties. 
  #
  # Include this into your ApplicationController
  #
  # If you've got more than one user model or a model named something otehr than user, then
  # set self.authenticated_system_model_class_name after inclusion.  (Default is User)
  module AuthenticatedSystem
    # Inclusion hook to make #current_user and #logged_in?, and similar methods
    # available as ActionView helper methods.
    def self.included(base)
      base.class_eval do
        class_inheritable_accessor :authenticated_system_model_class_name
        self.authenticated_system_model_class_name = 'User'
        
        helper_method :current_user, :logged_in?, :recognized_user, :recognized?
      protected
        attr_writer :access_denied_message, :access_denied_redirect
      end
    end

  protected
    def authenticated_system_model
      @authenticated_system_model ||= authenticated_system_model_class_name.constantize
    end
    
    def access_denied_message
      @access_denied_message ||= "You need to login before viewing that page"
    end
  
    def access_denied_redirect
      @access_denied_redirect ||= new_session_path
    end

    def recognized?
      recognized_user != :false
    end

    # Returns true or false if the user is logged in.
    # Preloads @current_user with the user model if they're logged in.
    def logged_in?
      current_user != :false
    end
  
    # Accesses the current user from the session.  Set it to :false if login fails
    # so that future calls do not hit the database.
    def current_user
      @current_user ||= (login_from_session || login_from_basic_auth || login_from_cookie || :false)
    end
  
    # Store the given user in the session.
    def current_user=(new_user)
      session[:user] = (new_user.nil? || new_user.is_a?(Symbol)) ? nil : new_user.id
      @current_user = new_user
    end
  
    def recognized_user
      @recognized_user ||= ((logged_in? && current_user) || recognize_from_cookie || :false)
    end
  
    # Check if the user is authorized
    #
    # Override this method in your controllers if you want to restrict access
    # to only a few actions or if you want to check if the user
    # has the correct rights.
    #
    # Example:
    #
    #  # only allow nonbobs
    #  def authorized?
    #    current_user.login != "bob"
    #  end
    def authorized?
      logged_in?
    end

    # Filter method to enforce a login requirement.
    #
    # To require logins for all actions, use this in your controllers:
    #
    #   before_filter :login_required
    #
    # To require logins for specific actions, use this in your controllers:
    #
    #   before_filter :login_required, :only => [ :edit, :update ]
    #
    # To skip this in a subclassed controller:
    #
    #   skip_before_filter :login_required
    #
    def login_required
      authorized? || access_denied
    end
  
    def recognition_required
      recognized? || access_denied
    end
  
    def action?(*action_names)
      action_names.collect(&:to_s).include? action_name
    end
  
    # Redirect as appropriate when an access request fails.
    #
    # The default action is to redirect to the login screen.
    #
    # Override this method in your controllers if you want to have special
    # behavior in case the user is not authorized
    # to access the requested action.  For example, a popup window might
    # simply close itself.
    def access_denied
      respond_to do |accepts|
        accepts.html  { html_access_denied }
        accepts.xml   { xml_access_denied }
      end
    end  
  
    def html_access_denied
      store_location
      flash[:error] = access_denied_message
      redirect_to access_denied_redirect
    end
    
    def xml_access_denied
      headers["Status"]           = "Unauthorized"
      headers["WWW-Authenticate"] = %(Basic realm="Web Password")
      render :text => "Could't authenticate you", :status => '401 Unauthorized'
    end
    
    # Store the URI of the current request in the session.
    #
    # We can return to this location by calling #redirect_to_stored_location.
    def store_location
      self.return_to = request.request_uri
    end
  
    def return_to
      session[:return_to]
    end
    
    def return_to=(uri)
      session[:return_to] = (uri.nil? ? nil : extract_path_from_uri(uri))
    end
    
    def forget_location
      self.return_to = nil
    end
  
    # If there's no location then store the referring url, unless its the current url
    def store_location_as_back_by_default
      self.return_to ||= request.env["HTTP_REFERER"]
    end
    
    def extract_path_from_uri(uri)
      uri = uri.gsub(%r(^\w+://[^/]+),'')
      uri[0..0] == '/' ? uri : "/#{uri}"
    end
  
    # Redirect to the URI stored by the most recent store_location call or
    # to the passed default.
    def redirect_to_stored_location(default = '/')
      return_to ? redirect_to(return_to) : redirect_to(default)
      forget_location
    end
  
    # Called from #current_user.  First attempt to login by the user id stored in the session.
    def login_from_session
      self.current_user = authenticated_system_model.find_by_id(session[:user]) if session[:user]
    end

    # Called from #current_user.  Now, attempt to login by basic authentication information.
    def login_from_basic_auth
      username, passwd = get_auth_data
      self.current_user = authenticated_system_model.authenticate(username, passwd) if username && passwd
    end

    # Called from #current_user.  Finaly, attempt to login by an expiring token in the cookie.
    def login_from_cookie      
      user = cookies[:auth_token] && authenticated_system_model.find_by_remember_token(cookies[:auth_token])
      if user && user.remember_token?
        user.remember_me
        cookies[:auth_token] = { :value => user.remember_token, :expires => user.remember_token_expires_at }
        self.current_user = user
      end
    end
  
    def recognize_from_cookie
      authenticated_system_model.find_by_recognition_token(cookies[:recognition_token]) if cookies[:recognition_token]
    end
  
  private
    @@http_auth_headers = %w(X-HTTP_AUTHORIZATION HTTP_AUTHORIZATION Authorization)
    # gets BASIC auth info
    def get_auth_data
      auth_key  = @@http_auth_headers.detect { |h| request.env.has_key?(h) }
      auth_data = request.env[auth_key].to_s.split unless auth_key.blank?
      return auth_data && auth_data[0] == 'Basic' ? Base64.decode64(auth_data[1]).split(':')[0..1] : [nil, nil] 
    end
  end
end
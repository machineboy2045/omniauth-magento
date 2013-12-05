# Omniauth::Magento

An Omniauth strategy for Magento. Works only with the newer Magento REST api (not SOAP).

## Instructions on how to use with Rails

### Setting up Magento

* [Set up a consumer in Magento](http://www.magentocommerce.com/api/rest/authentication/oauth_configuration.html) and write down consumer key and consumer secret
* In the Magento Admin backend, go to System > Web Services > REST Roles, select Customer, and tick "Retrieve" under "Customer"
* In the Magento Admin backend, go to System > Web Services > REST Attributes, select Customer, and tick "Email", "First name" and "Last name" under "Customer" > "Read".

### Setting up Rails

* Install Devise if it's not installed
* Read [OmniAuth instructions](https://github.com/plataformatec/devise/wiki/OmniAuth:-Overview)
* Load this library into your Gemfile: `gem "omniauth-magento", github: "Zookal/omniauth-magento"`
* Run `bundle install`
* Configure config/initializers/devise.rb:

```
Devise.setup do |config|
  # deactivate SSL on development environment
  OpenSSL::SSL::VERIFY_PEER ||= OpenSSL::SSL::VERIFY_NONE if Rails.env.development? 
  config.omniauth :magento, ENTER_YOUR_MAGENTO_CONSUMER_KEY, ENTER_YOUR_MAGENTO_CONSUMER_SECRET
```

* Make sure you have columns first_name, last_name, magento_id, email in your User table
* Add this line to your view `<%= link_to "Sign in with Magento", user_omniauth_authorize_path(:magento) %>`
* Add / replace this line in your routes.rb `devise_for :users, :controllers => { :omniauth_callbacks => "users/omniauth_callbacks" }`. This will be called once Magento has successfully authorized and returns to the Rails app.
* In your folder controllers, create a subfolder users
* In that subfolder app/controllers/users/omniauth_callbacks_controller.rb, create a file with the following code (from Devise wiki linked above):

```
class Users::OmniauthCallbacksController < Devise::OmniauthCallbacksController
  def magento
    # You need to implement the method below in your model (e.g. app/models/user.rb)
    @user = User.find_for_magento_oauth(request.env["omniauth.auth"], current_user)

    if @user.persisted?
      sign_in_and_redirect @user, :event => :authentication #this will throw if @user is not activated
      set_flash_message(:notice, :success, :kind => "magento") if is_navigational_format?
    else
      session["devise.magento_data"] = request.env["omniauth.auth"]
      redirect_to new_user_registration_url
    end
  end
end
```

* Set up your User model to be omniauthable `:omniauthable, :omniauth_providers => [:magento]` and to contain the `find_for_magento_oauth` method

```
class User < ActiveRecord::Base  
  devise :database_authenticatable, :registerable, :recoverable,
         :rememberable, :trackable, :validatable, :timeoutable
         :omniauthable, :omniauth_providers => [:magento]  

  def self.find_for_magento_oauth(auth, signed_in_resource=nil)
    user = User.find_by(magento_id: auth.uid)
    unless user
      user = User.create!(
        first_name: auth.info.first_name,                           
        last_name:  auth.info.last_name,
        magento_id: auth.uid,
        email:      auth.info.email,
        password:   Devise.friendly_token[0,20]
      )
    end
    user
  end         
end
```

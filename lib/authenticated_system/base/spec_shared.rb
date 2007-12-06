# to use these shared examples just set @model beforehand

describe "AuthenticatedSystem::Base (re: current_password)", :shared => true do
  it "when current_password correct, should update password" do
    @model.attributes = {:current_password => @model.password, :password => 'newone', :password_confirmation => 'newone'}
    @model.save.should be_true
    @model.class.authenticate(@model.email, 'newone').should_not be_nil
  end
  
  it "when current_password incorrect, should add validation error" do
    @model.attributes = {:current_password => @model.password + "crud", :password => 'newone', :password_confirmation => 'newone'}
    @model.should have(1).error_on(:current_password)
  end

  it "when current_password correct, should update email" do
    @model.attributes = {:current_password => @model.password, :email => 'foo@changed.com'}
    @model.save.should be_true
    User.find(@model.id).email.should == 'foo@changed.com'
  end
  
  it "when current_password incorrect, should add validation error" do
    @model.attributes = {:current_password => @model.password + "crud", :email => 'foo@changed.com' }
    @model.should have(1).error_on(:current_password)
  end
end

# this is included in (activated) below
describe "AuthenticatedSystem::Base (re: password hashing)", :shared => true do
  it "should be able to reset password with current_password" do
    @model.update_attributes(:password => 'new password', :password_confirmation => 'new password', :current_password => @model.password)
    @model.class.authenticate(@model.email, 'new password').should == @model
  end

  it "should not rehash password when password not updated" do
    @model.update_attributes(:email => 'quentin2@oobla.com', :current_password => @model.password)
    @model.class.authenticate('quentin2@oobla.com', @model.password).should == @model
  end
end

# this is included in (activated) below
describe "AuthenticatedSystem::Base (re: reset_password)", :shared => true do
  it "#request_reset_password should set remember_token for 1 hour" do
    @model.request_reset_password
    @model.remember_token.should_not be_nil
    @model.remember_token_expires_at.should > Time.now + 59.minutes
    @model.remember_token_expires_at.should < Time.now + 60.minutes
  end
end

# this is included in (activated) below
describe "AuthenticatedSystem::Base (re: request_activation)", :shared => true do
  it "#request_activation should set activated_at to nil" do
    @model.request_activation
    @model.activated_at.should be_nil
  end
  
  it "#request_activation should make_activation_code" do
    @model.should_receive(:make_activation_code)
    @model.request_activation
  end
end

# this is included in (activated) below
describe "AuthenticatedSystem::Base (re: remember_me)", :shared => true do
  it "#remember_me should set remember token" do
    @model.remember_me
    @model.remember_token.should_not be_nil
    @model.remember_token_expires_at.should_not be_nil
  end

  it "#forget_me should unset remember token" do
    @model.remember_me
    @model.remember_token.should_not be_nil
    @model.forget_me
    @model.remember_token.should be_nil
  end

  it "#remember_me_for 1.week, should remember me for one week" do
    before = 1.week.from_now.utc
    @model.remember_me_for 1.week
    after = 1.week.from_now.utc
    @model.remember_token.should_not be_nil
    @model.remember_token_expires_at.should_not be_nil
    @model.remember_token_expires_at.should be_between(before, after)
  end

  it "#remember_me_until 1.week.from_now.utc, should remember me until one week" do
    time = 1.week.from_now.utc
    @model.remember_me_until time
    @model.remember_token.should_not be_nil
    @model.remember_token_expires_at.should_not be_nil
    @model.remember_token_expires_at.should == time
  end

  it "#remember_me should remember me for two weeks by default" do
    before = 2.week.from_now.utc
    @model.remember_me
    after = 2.week.from_now.utc
    @model.remember_token.should_not be_nil
    @model.remember_token_expires_at.should_not be_nil
    @model.remember_token_expires_at.should be_between(before, after)
  end
end

describe 'AuthenticatedSystem::Base (validation)', :shared => true do
  it "should require password" do
    @model.password= nil
    @model.should have_at_least(1).errors_on(:password)
  end

  it "should require password_confirmation" do
    @model.password_confirmation= nil
    @model.should have_at_least(1).errors_on(:password_confirmation)
  end

  it "should require email" do
    @model.email = nil
    @model.should have_at_least(1).errors_on(:email)
  end
  
  it "should require unique email" do
    @model.save.should be_true # save current email
    other = @model.class.new(@model.attributes)
    other.should have_at_least(1).errors_on(:email)
  end
  
  [:remember_token, :recognition_token, :crypted_password, :salt, :activation_code, :remember_token_expires_at, :activated_at, :current_password_required].each do |attr|
    it "should protect #{attr} from mass_assignment" do
      value = @model[attr]
      @model.attributes = {attr => !value}
      @model[attr].should == value
    end
  end
end

describe "AuthenticatedSystem::Base (created)", :shared => true do
  it "should not be activated" do
    @model.should_not be_activated
  end
  
  it "should allow activation" do
    @model.activate
    @model.should be_activated
  end
  
  it "should have a recognition_token" do
    @model.recognition_token.should_not be_nil
  end
  
  it "should not authenticate user" do
    @model.class.authenticate(@model.email, @model.password).should be_nil
  end
end

describe "AuthenticatedSystem::Base (activated)", :shared => true do
  it "should be activated" do
    @model.should be_activated
  end
  
  it "should authenticate user with email and unencrypted password" do
    @model.class.authenticate(@model.email, @model.password).should == @model
  end
  
  it_should_behave_like "AuthenticatedSystem::Base (re: password hashing)"
  it_should_behave_like "AuthenticatedSystem::Base (re: remember_me)"
  it_should_behave_like "AuthenticatedSystem::Base (re: reset_password)"
  it_should_behave_like "AuthenticatedSystem::Base (re: request_activation)"
  it_should_behave_like "AuthenticatedSystem::Base (re: current_password)"
end
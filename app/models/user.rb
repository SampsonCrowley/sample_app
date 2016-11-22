class User < ApplicationRecord
  attr_accessor :password_confirmation
  before_save do
    email.downcase!
    self.password = User.digest(password)
  end

  validates :name,  presence: true, length: { maximum: 50 }
  VALID_EMAIL_REGEX = /\A[\w+\-.]+@[a-z\d\-]+(\.[a-z\d\-]+)*\.[a-z]+\z/i
  validates :email, presence:   true, length: { maximum: 255 },
                    format:     { with: VALID_EMAIL_REGEX },
                    uniqueness: { case_sensitive: false }

  validates :password, presence: true, length: { minimum: 8 }
  validate do
    errors.add(:password, "passwords must match") if password != password_confirmation
  end

  def User.digest(pass)
    SCrypt::Engine.calibrate!(max_mem: 16 * 1024 * 1024, key_len: 256)
    SCrypt::Password.create(pass)
  end
end

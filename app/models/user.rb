class User < ApplicationRecord
  # Include default devise modules. Others available are:
  # :confirmable, :lockable, :timeoutable and :omniauthable
  devise :database_authenticatable, :registerable,
         :recoverable, :rememberable, :trackable, :validatable
  has_secure_password
  VALID_EMAIL_REGEX = /[\wа-я\.\+]+@([\wа-я]+\.?)+/i
  validates :email, presence: true, uniqueness: true, format: { with: VALID_EMAIL_REGEX }
  validates :password, presence: true
  validates :password_confirmation, presence: true
  before_save { self.email = email.downcase }
end

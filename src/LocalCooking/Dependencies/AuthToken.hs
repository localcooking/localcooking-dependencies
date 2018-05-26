{-# LANGUAGE
    NamedFieldPuns
  , OverloadedStrings
  , OverloadedLists
  , MultiParamTypeClasses
  , DeriveGeneric
  , FlexibleContexts
  , GeneralizedNewtypeDeriving
  #-}

module LocalCooking.Dependencies.AuthToken where

import LocalCooking.Function.System (AppM, SystemEnv (..), Managers (..), TokenContexts (..), Keys (..), getUserId)
import LocalCooking.Function.Common (login, socialLogin)
import LocalCooking.Semantics.Common (Login (..), SocialLogin (..))
import LocalCooking.Common.User.Password (HashedPassword)
import LocalCooking.Common.AccessToken.Auth (AuthToken)
import LocalCooking.Dependencies.AccessToken.Generic (AccessTokenInitIn (..), AccessTokenInitOut (..), AccessTokenDeltaOut (..), accessTokenServer)
import Text.EmailAddress (EmailAddress)
import Facebook.Types (FacebookLoginCode, FacebookUserId)
import Facebook.Return (FacebookLoginReturnError, handleFacebookLoginReturn)

import Web.Dependencies.Sparrow (Server)
import Data.Aeson (FromJSON (..), ToJSON (..), object, (.=), (.:), Value (..))
import Data.Aeson.Types (typeMismatch)
import Data.Text (Text)
import Control.Applicative ((<|>))
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Reader (ask)
import Control.Newtype (Newtype (unpack, pack))
import Test.QuickCheck (Arbitrary (..), oneof)
import GHC.Generics (Generic)



data AuthTokenInitIn
  = AuthTokenInitInLogin
    { authTokenInitInLogin :: Login
    }
  | AuthTokenInitInSocialLogin
    { authTokenInitInSocialLogin :: SocialLogin
    }
  | AuthTokenInitInExists
    { authTokenInitInExists :: AuthToken
    }

instance FromJSON AuthTokenInitIn where
  parseJSON json = case json of
    Object o -> do
      let exists = AuthTokenInitInExists <$> o .: "exists"
          socialLogin' = AuthTokenInitInSocialLogin <$> o .: "socialLogin"
          login' = AuthTokenInitInLogin <$> o .: "login"
      exists <|> socialLogin' <|> login'
    _ -> fail'
    where
      fail' = typeMismatch "AuthTokenInitIn" json

instance AccessTokenInitIn AuthTokenInitIn where
  getExists initIn = case initIn of
    AuthTokenInitInExists x -> Just (unpack x)
    _ -> Nothing






-- | Global AuthToken failure type
data AuthTokenFailure
  = FBLoginReturnBad Text Text
  | FBLoginReturnDenied Text
  | FBLoginReturnBadParse
  | FBLoginReturnNoUser FacebookUserId
  | FBLoginReturnError FacebookLoginReturnError
  | AuthTokenLoginFailure
  deriving (Eq, Show, Generic)

instance Arbitrary AuthTokenFailure where
  arbitrary = oneof
    [ FBLoginReturnBad <$> arbitrary <*> arbitrary
    , FBLoginReturnDenied <$> arbitrary
    , pure FBLoginReturnBadParse
    , FBLoginReturnNoUser <$> arbitrary
    , pure AuthTokenLoginFailure
    , FBLoginReturnError <$> arbitrary
    ]

instance ToJSON AuthTokenFailure where
  toJSON x = case x of
    FBLoginReturnBad code msg -> object
      [ "fbBad" .= object
        [ "code" .= code
        , "msg" .= msg
        ]
      ]
    FBLoginReturnDenied desc -> object
      [ "fbDenied" .= object
        [ "desc" .= desc
        ]
      ]
    FBLoginReturnBadParse -> String "bad-parse"
    FBLoginReturnNoUser x -> object
      [ "no-user" .= x
      ]
    FBLoginReturnError x -> object
      [ "fbLoginReturnError" .= x
      ]
    AuthTokenLoginFailure -> String "loginFailure"

instance FromJSON AuthTokenFailure where
  parseJSON json = case json of
    Object o -> do
      let denied = do
            o' <- o .: "fbDenied"
            FBLoginReturnDenied <$> o' .: "desc"
          bad = do
            o' <- o .: "fbBad"
            FBLoginReturnBad <$> o' .: "code" <*> o' .: "msg"
          fbLoginReturnError = FBLoginReturnError <$> o .: "fbLoginReturnError"
          noUser = FBLoginReturnNoUser <$> o .: "no-user"
      denied <|> bad <|> fbLoginReturnError <|> noUser
    String s
      | s == "bad-parse" -> pure FBLoginReturnBadParse
      | s == "loginFailiure" -> pure AuthTokenLoginFailure
      | otherwise -> fail'
    _ -> fail'
    where
      fail' = typeMismatch "AuthError" json



newtype PreliminaryAuthToken = PreliminaryAuthToken
  { getPreliminaryAuthToken :: Maybe (Either AuthTokenFailure AuthToken)
  } deriving (Eq, Show, Generic, Arbitrary)

instance ToJSON PreliminaryAuthToken where
  toJSON (PreliminaryAuthToken mTkn) = case mTkn of
    Nothing -> toJSON (Nothing :: Maybe ())
    Just eTkn -> case eTkn of
      Left e -> object ["err" .= e]
      Right tkn -> object ["token" .= tkn]

instance FromJSON PreliminaryAuthToken where
  parseJSON (Object o) = do
    let err = Left <$> o .: "err"
        tkn = Right <$> o .: "token"
    PreliminaryAuthToken . Just <$> (err <|> tkn)
  parseJSON Null = pure (PreliminaryAuthToken Nothing)
  parseJSON x = typeMismatch "PreliminaryAuthToken" x




data AuthTokenInitOut
  = AuthTokenInitOutSuccess AuthToken
  | AuthTokenInitOutFailure AuthTokenFailure

instance ToJSON AuthTokenInitOut where
  toJSON x = case x of
    AuthTokenInitOutFailure e -> object ["failure" .= e]
    AuthTokenInitOutSuccess y -> object ["success" .= y]

instance AccessTokenInitOut AuthTokenInitOut AuthTokenFailure where
  makeSuccess = AuthTokenInitOutSuccess . pack
  makeFailure = AuthTokenInitOutFailure



data AuthTokenDeltaIn
  = AuthTokenDeltaInLogout -- TODO plus AuthToken...? Tokens are --more-- mutually unique than SIDs?
    -- a session can die, but store the AuthToken in local storage and attempt to use later -
    -- login's discontinuity and session's discontinuity mutually overlay.

instance FromJSON AuthTokenDeltaIn where
  parseJSON json = case json of
    String x | x == "logout" -> pure AuthTokenDeltaInLogout
             | otherwise -> fail'
    _ -> fail'
    where
      fail' = typeMismatch "AuthTokenDeltaIn" json


data AuthTokenDeltaOut
  = AuthTokenDeltaOutRevoked -- remotely logged out

instance ToJSON AuthTokenDeltaOut where
  toJSON x = case x of
    AuthTokenDeltaOutRevoked -> String "revoked"

instance AccessTokenDeltaOut AuthTokenDeltaOut where
  makeRevoke = AuthTokenDeltaOutRevoked



authTokenServer :: Server AppM [] AuthTokenInitIn
                                  AuthTokenInitOut
                                  AuthTokenDeltaIn
                                  AuthTokenDeltaOut
authTokenServer initIn = do
  SystemEnv
    { systemEnvTokenContexts = TokenContexts
      { tokenContextAuth
      }
    } <- ask

  let getAuthToken :: AuthTokenInitIn -> AppM (Either (Maybe AuthTokenFailure) AuthToken)
      getAuthToken initIn' = case initIn' of
        -- invoked remotely from a client whenever casually attempting a normal login
        AuthTokenInitInLogin creds -> do
          mAuthToken <- login creds
          pure $ case mAuthToken of
            Nothing -> Left $ Just AuthTokenLoginFailure
            Just authToken -> Right authToken

        -- invoked remotely from client when started with an authToken in frontendEnv, or in localStorage;
        -- we don't consider handling it here because that's automatic in AccessToken.Generic.
        AuthTokenInitInExists _ -> pure (Left Nothing)

        -- invoked on facebookLoginReturn, only when the user exists
        AuthTokenInitInSocialLogin creds -> do
          eAuthToken <- socialLogin creds
          pure $ case eAuthToken of
            Left mE -> case mE of
              Just e -> Left $ Just $ FBLoginReturnError e
              Nothing -> Left Nothing
            Right authToken -> Right authToken

  accessTokenServer tokenContextAuth getAuthToken
    (\revoke AuthTokenDeltaInLogout -> revoke)
    (\_ -> pure ()) initIn

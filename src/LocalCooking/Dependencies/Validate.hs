module LocalCooking.Dependencies.Validate where

import LocalCooking.Function.Validate (uniqueEmail)
import LocalCooking.Function.System (AppM)

import Text.EmailAddress (EmailAddress)
import Data.Aeson.JSONUnit (JSONUnit, boolToUnit)
import Web.Dependencies.Sparrow.Types (Server, staticServer, JSONVoid)


uniqueEmailServer :: Server AppM [] EmailAddress JSONUnit JSONVoid JSONVoid
uniqueEmailServer = staticServer (fmap boolToUnit . uniqueEmail)

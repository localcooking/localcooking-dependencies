module LocalCooking.Dependencies.Common where

import LocalCooking.Dependencies.AuthToken
  (WithAuthTokenIn (withAuthTokenAuthToken), uncurryWithAuthToken)
import LocalCooking.Semantics.Common (Register, User)
import LocalCooking.Function.Common (register, getUser, setUser)
import LocalCooking.Function.System (AppM)

import Data.Aeson.JSONUnit (JSONUnit, boolToUnit)
import Web.Dependencies.Sparrow.Types (Server, staticServer, JSONVoid)



registerServer :: Server AppM [] Register JSONUnit JSONVoid JSONVoid
registerServer = staticServer (fmap boolToUnit . register)


getUserServer :: Server AppM [] (WithAuthTokenIn JSONUnit) User JSONVoid JSONVoid
getUserServer = staticServer (getUser . withAuthTokenAuthToken)


setUserServer :: Server AppM [] (WithAuthTokenIn User) JSONUnit JSONVoid JSONVoid
setUserServer = staticServer (fmap boolToUnit . uncurryWithAuthToken setUser)


{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TupleSections #-}

module Main
  ( main,
  )
where

import qualified Args
import qualified ConfigFile
import Control.Applicative (Alternative ((<|>)))
import Control.Monad
  ( forM,
    forM_,
  )
import qualified Data.Aeson.Encode.Pretty as AesonP
import qualified Data.ByteString.Lazy.Char8 as BS
import Data.List.NonEmpty (NonEmpty ((:|)))
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Env
import qualified Keycloak
import Network.HTTP.Client.TLS (newTlsManager)
import qualified Options.Applicative.Help as Help
import qualified Rest
import qualified Servant.Client as SC
import System.Environment (getProgName)

main :: IO ()
main =
  Args.getArgs >>= \args -> do
    env <- Env.getEnv
    configFile <-
      eitherToMaybe
        <$> ConfigFile.parse
          (maybe ConfigFile.defaultConfigFiles (:| []) $ Args.configFile args)
    let auth =
          Args.credentials args
            <|> Env.auth env
            <|> (configFile >>= ConfigFile.apiKey)
    let endpoint =
          maybe Keycloak.defaultBaseUrl Env.asBaseUrl $
            Args.endpoint args
              <|> Env.endpoint env
              <|> (configFile >>= ConfigFile.endpoint)
    case auth of
      Nothing -> do
        progName <- getProgName
        Help.putDoc $
          "Please set the credentials. Run "
            <> Help.underline (Help.text progName <> " credentials")
            <> " for more info."
            <> Help.hardline
      Just auth' -> command endpoint auth' (Args.command args)
  where
    command endpoint auth Args.Authenticate = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run' endpoint (Keycloak.authenticateQuery kc Keycloak.OpenidConnect)
        >>= display
    command endpoint auth (Args.CreateClient realm clientInfo) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            Rest.create (Keycloak.clientQueries kc' token) clientInfo
        )
        >>= either (displayErr . Keycloak.parseError) print
    command endpoint auth (Args.ListClients realm) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            Rest.list (Keycloak.clientQueries kc' token)
        )
        >>= \case
          Left err' -> displayErr $ Keycloak.parseError err'
          Right cis ->
            forM_ cis $
              putStrLn . \ciwr ->
                T.unpack (Rest.unResourceID (Rest.resourceID ciwr))
                  <> " "
                  <> T.unpack (Keycloak.ciClientId (Rest.resourceInfo ciwr))
    command endpoint auth (Args.ShowClient realm clientIDs) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            forM clientIDs $ \c ->
              getClientResourceID kc' token c
                >>= Rest.get (Keycloak.clientQueries kc' token)
        )
        >>= either
          (displayErr . Keycloak.parseError)
          (BS.putStrLn . AesonP.encodePretty)
    command endpoint auth (Args.DeleteClient realm clientIDs) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            forM clientIDs $ \c ->
              getClientResourceID kc' token c
                >>= Rest.delete (Keycloak.clientQueries kc' token)
        )
        >>= either (displayErr . Keycloak.parseError) (\_ -> return ())
    command endpoint auth (Args.ShowSecret realm clientIdentifier) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            getClientResourceID kc' token clientIdentifier
              >>= Keycloak.getSecret (Keycloak.secretQueries kc' token)
        )
        >>= either
          (displayErr . Keycloak.parseError)
          (BS.putStrLn . AesonP.encodePretty)
    command endpoint auth (Args.CreateProtocol realm clientIdentifier protocolMapper) =
      do
        let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
        run'
          endpoint
          ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
              let kc' = Keycloak.mkClient auth realm
              getClientResourceID kc' token clientIdentifier >>= \clientID ->
                Rest.create
                  (Keycloak.protocolMapperQueries kc' token clientID)
                  protocolMapper
          )
          >>= either (displayErr . Keycloak.parseError) print
    command endpoint auth (Args.ListProtocols realm clientIdentifier) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            getClientResourceID kc' token clientIdentifier
              >>= Rest.list
                . Keycloak.protocolMapperQueries kc' token
        )
        >>= \case
          Left err' -> displayErr $ Keycloak.parseError err'
          Right cis ->
            forM_ cis $
              putStrLn . \protocol ->
                T.unpack (Rest.unResourceID (Rest.resourceID protocol))
                  <> " "
                  <> show (Keycloak.pName (Rest.resourceInfo protocol))
    command endpoint auth (Args.ShowProtocol realm clientIdentifier protocolIDs) =
      do
        let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
        run'
          endpoint
          ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
              let kc' = Keycloak.mkClient auth realm
              getClientResourceID kc' token clientIdentifier >>= \clientID ->
                forM protocolIDs $ \p ->
                  getProtocolMapperResourceID kc' token clientID p
                    >>= Rest.get
                      (Keycloak.protocolMapperQueries kc' token clientID)
          )
        >>= either
          (displayErr . Keycloak.parseError)
          (BS.putStrLn . AesonP.encodePretty)
    command endpoint auth (Args.DeleteProtocol realm clientIdentifier protocolIDs) =
      do
        let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
        run'
          endpoint
          ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
              let kc' = Keycloak.mkClient auth realm
              getClientResourceID kc' token clientIdentifier >>= \clientID ->
                forM protocolIDs $ \p ->
                  getProtocolMapperResourceID kc' token clientID p
                    >>= Rest.delete
                      (Keycloak.protocolMapperQueries kc' token clientID)
          )
          >>= either (displayErr . Keycloak.parseError) (\_ -> return ())
    command endpoint auth (Args.ListUsers realm) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            Rest.list (Keycloak.userQueries kc' token)
        )
        >>= \case
          Left err' -> displayErr $ Keycloak.parseError err'
          Right cis ->
            forM_ cis $
              putStrLn . \ciwr ->
                T.unpack (Rest.unResourceID (Rest.resourceID ciwr))
                  <> " "
                  <> T.unpack (Keycloak.uUsername (Rest.resourceInfo ciwr))
    command endpoint auth (Args.ShowUser realm userIDs) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            forM userIDs $ \u ->
              getUserResourceID kc' token u
                >>= Rest.get (Keycloak.userQueries kc' token)
        )
        >>= either
          (displayErr . Keycloak.parseError)
          (BS.putStrLn . AesonP.encodePretty)
    command endpoint auth (Args.ListRoleMappings realm userID clientID) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            getUserResourceID kc' token userID >>= \userID' ->
              getClientResourceID kc' token clientID >>= \clientID' -> do
                let queries =
                      Keycloak.roleMappingQueries kc' token userID' clientID'
                used <- Keycloak.list queries
                available <- Keycloak.listAvailable queries
                return $ map (True,) used ++ map (False,) available
        )
        >>= \case
          Left err' -> displayErr $ Keycloak.parseError err'
          Right cis ->
            forM_ cis $
              putStrLn . \(used, rm) ->
                T.unpack (Rest.unResourceID (Rest.resourceID rm))
                  <> " "
                  <> (if used then "[used]     " else "[available]")
                  <> " "
                  <> T.unpack (Keycloak.rmName (Rest.resourceInfo rm))
    command endpoint auth (Args.ShowRoleMappings realm userID clientID rmIDs) =
      do
        let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
        run'
          endpoint
          ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
              let kc' = Keycloak.mkClient auth realm
              getUserResourceID kc' token userID >>= \userID' ->
                getClientResourceID kc' token clientID >>= \clientID' ->
                  forM rmIDs $ \rmID ->
                    getRoleMappingResourceID kc' token userID' clientID' rmID
                      >>= Keycloak.get
                        ( Keycloak.roleMappingQueries kc' token userID' clientID'
                        )
          )
        >>= either
          (displayErr . Keycloak.parseError)
          (BS.putStrLn . AesonP.encodePretty)
    command endpoint auth (Args.AddRoleMapping realm userID clientID rmIDs) = do
      let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
      run'
        endpoint
        ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
            let kc' = Keycloak.mkClient auth realm
            getUserResourceID kc' token userID >>= \userID' ->
              getClientResourceID kc' token clientID >>= \clientID' ->
                forM rmIDs $ \rmID ->
                  getRoleMappingResourceID kc' token userID' clientID' rmID
                    >>= Keycloak.add
                      ( Keycloak.roleMappingQueries kc' token userID' clientID'
                      )
        )
        >>= either (displayErr . Keycloak.parseError) (\_ -> return ())
    command endpoint auth (Args.DeleteRoleMapping realm userID clientID rmIDs) =
      do
        let kc = Keycloak.mkClient auth (Keycloak.Realm "master")
        run'
          endpoint
          ( Keycloak.authenticateQuery kc Keycloak.OpenidConnect >>= \token -> do
              let kc' = Keycloak.mkClient auth realm
              getUserResourceID kc' token userID >>= \userID' ->
                getClientResourceID kc' token clientID >>= \clientID' ->
                  forM rmIDs $ \rmID ->
                    getRoleMappingResourceID kc' token userID' clientID' rmID
                      >>= Keycloak.delete
                        ( Keycloak.roleMappingQueries
                            kc'
                            token
                            userID'
                            clientID'
                        )
          )
          >>= either (displayErr . Keycloak.parseError) (\_ -> return ())

    getClientResourceID ::
      Keycloak.KeycloakClient ->
      Keycloak.AuthToken ->
      Args.ClientIdentifier ->
      SC.ClientM Rest.ResourceID
    getClientResourceID kc' token = \case
      Args.ResourceID resourceID -> return resourceID
      Args.ClientID clientID ->
        Rest.getByName (Keycloak.clientQueries kc' token) clientID
          >>= \Rest.WithResourceID {resourceID} -> return resourceID

    getProtocolMapperResourceID ::
      Keycloak.KeycloakClient ->
      Keycloak.AuthToken ->
      Rest.ResourceID ->
      Args.ProtocolMapperIdentifier ->
      SC.ClientM Rest.ResourceID
    getProtocolMapperResourceID kc' token clientID = \case
      Args.ProtocolResourceID resourceID -> return resourceID
      Args.ProtocolName protocolName ->
        Rest.getByName
          (Keycloak.protocolMapperQueries kc' token clientID)
          protocolName
          >>= \Rest.WithResourceID {resourceID} -> return resourceID

    getUserResourceID ::
      Keycloak.KeycloakClient ->
      Keycloak.AuthToken ->
      Args.UserIdentifier ->
      SC.ClientM Rest.ResourceID
    getUserResourceID kc' token = \case
      Args.UserResourceID resourceID -> return resourceID
      Args.UserID userID ->
        Rest.getByName (Keycloak.userQueries kc' token) userID
          >>= \Rest.WithResourceID {resourceID} -> return resourceID

    getRoleMappingResourceID ::
      Keycloak.KeycloakClient ->
      Keycloak.AuthToken ->
      Rest.ResourceID ->
      Rest.ResourceID ->
      Args.RoleMappingIdentifier ->
      SC.ClientM Rest.ResourceID
    getRoleMappingResourceID kc' token userID clientID = \case
      Args.RoleMappingResourceID resourceID -> return resourceID
      Args.RoleMappingID rmID ->
        Keycloak.getByName
          (Keycloak.roleMappingQueries kc' token userID clientID)
          rmID
          >>= \Rest.WithResourceID {resourceID} -> return resourceID

display :: Show a => Either SC.ClientError a -> IO ()
display (Left err) = displayErr $ Keycloak.parseError err
display (Right x) = print x

run' :: SC.BaseUrl -> SC.ClientM a -> IO (Either SC.ClientError a)
run' endpoint query = do
  manager' <- newTlsManager
  SC.runClientM query (SC.mkClientEnv manager' endpoint)

displayErr :: Keycloak.Error -> IO ()
displayErr = displayErr' Nothing

displayErr' :: Maybe Text -> Keycloak.Error -> IO ()
displayErr' prefix err =
  let prefix' = T.unpack $ fromMaybe "" prefix
   in case err of
        Keycloak.Error Keycloak.Status {statusCode, statusMessage} e ->
          putStrLn $
            prefix'
              <> "got an error from Keycloak: ["
              <> show statusCode
              <> "] "
              <> statusMessage
              <> ":\n"
              <> printError e
          where
            printError :: Keycloak.KeycloakError -> String
            printError Keycloak.KeycloakError {..} =
              maybe "" (\e' -> "[" <> e' <> "] ") keycloakError
                <> fromMaybe "" keycloakErrorDescription
                <> fromMaybe "" keycloakErrorMessage
        Keycloak.DecodeError Keycloak.Status {statusCode, statusMessage} e decodeError ->
          putStrLn $
            prefix'
              <> "got an error \""
              <> decodeError
              <> "\" while decoding a response from Keycloak ["
              <> show statusCode
              <> "] "
              <> statusMessage
              <> ": "
              <> e
        Keycloak.ConnectionError e ->
          putStrLn $
            prefix'
              <> "got a connection error while talking with Keycloak: "
              <> e
        Keycloak.OtherError Keycloak.Status {statusCode, statusMessage} e ->
          putStrLn $
            prefix'
              <> "got an error status code from Keycloak ["
              <> show statusCode
              <> "] "
              <> statusMessage
              <> ": "
              <> e

mapLeft :: (a -> b) -> Either a c -> Either b c
mapLeft f (Left a) = Left $ f a
mapLeft _ (Right b) = Right b

mapRight :: (c -> d) -> Either a c -> Either a d
mapRight _ (Left a) = Left a
mapRight f (Right b) = Right $ f b

eitherToMaybe :: Either a b -> Maybe b
eitherToMaybe (Left _) = Nothing
eitherToMaybe (Right b) = Just b

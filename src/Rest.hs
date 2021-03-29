{-# LANGUAGE DataKinds #-}
{-# LANGUAGE DeriveGeneric #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE TypeApplications #-}
{-# LANGUAGE TypeOperators #-}

-- |
module Rest
  ( ResourceID (..),
    WithResourceID (..),
    API,
    APIQueries (..),
    mkAPIQueries,
  )
where

import Control.Exception (Exception)
import Control.Monad.Catch (MonadThrow (throwM))
import Data.Aeson
  ( FromJSON (..),
    ToJSON (..),
    (.:),
  )
import qualified Data.Aeson as Aeson
import qualified Data.HashMap.Strict as HashMap
import Data.Text (Text)
import qualified Data.Text as T
import GHC.Generics (Generic)
import Servant ((:<|>) (..), (:>))
import qualified Servant as S
import qualified Servant.Client as SC

newtype ResourceID = ResourceID {unResourceID :: Text}
  deriving (Generic)

instance Show ResourceID where
  show = T.unpack . unResourceID

instance FromJSON ResourceID where
  parseJSON =
    Aeson.withText "id" (pure . ResourceID)

instance S.FromHttpApiData ResourceID where
  -- The url piece is the complete URL, including the hostname. We
  -- assume the ResourceID is the last path of the URL.
  parseUrlPiece = fmap ResourceID . last' . T.splitOn "/"
    where
      last' [] = Left "could not parse resourceID"
      last' [x] = Right x
      last' (_ : xs) = last' xs

instance S.ToHttpApiData ResourceID where
  toUrlPiece = unResourceID

data WithResourceID a = WithResourceID
  { resourceID :: ResourceID,
    resourceInfo :: a
  }
  deriving (Generic)

instance (Show a) => Show (WithResourceID a) where
  show (WithResourceID id' info) = T.unpack (unResourceID id') <> ":\n" <> show info

instance (FromJSON a) => FromJSON (WithResourceID a) where
  parseJSON v =
    WithResourceID
      <$> Aeson.withObject "id" (.: "id") v
        <*> Aeson.parseJSON v

instance (ToJSON a) => ToJSON (WithResourceID a) where
  toJSON (WithResourceID id' info) = case toJSON info of
    Aeson.Object hashMap -> Aeson.Object (hashMap <> HashMap.singleton "id" (Aeson.String (unResourceID id')))
    other -> other

type API filterParam t =
  -- List
  filterParam :> S.Get '[S.JSON] [WithResourceID t]
    -- Create
    :<|> S.ReqBody '[S.JSON] t :> S.Post '[S.OctetStream] (S.Headers '[S.Header "Location" ResourceID] S.NoContent)
    -- Update
    :<|> S.Capture "resourceID" ResourceID :> S.ReqBody '[S.JSON] (WithResourceID t) :> S.Put '[S.OctetStream] S.NoContent
    -- Get
    :<|> S.Capture "resourceID" ResourceID :> S.Get '[S.JSON] (WithResourceID t)
    -- Delete
    :<|> S.Capture "resourceID" ResourceID :> S.Delete '[S.JSON] S.NoContent

data NoItemFound = NoItemFound

instance Show NoItemFound where
  show _ = "No item found"

instance Exception NoItemFound

data TooManyItemsFound = TooManyItemsFound

instance Show TooManyItemsFound where
  show _ = "Too many items found"

instance Exception TooManyItemsFound

data MissingHeader = MissingHeader

instance Show MissingHeader where
  show _ = "Missing header"

instance Exception MissingHeader

data UndecodableHeader = UndecodableHeader

instance Show UndecodableHeader where
  show _ = "Undecodable header"

instance Exception UndecodableHeader

mkAPIQueries ::
  (Eq name) =>
  (Maybe name -> SC.ClientM [WithResourceID t])
    :<|> (t -> SC.ClientM (S.Headers '[S.Header "Location" ResourceID] S.NoContent))
    :<|> (ResourceID -> WithResourceID t -> SC.ClientM S.NoContent)
    :<|> (ResourceID -> SC.ClientM (WithResourceID t))
    :<|> (ResourceID -> SC.ClientM S.NoContent) ->
  (t -> name) ->
  APIQueries name t
mkAPIQueries api nameFilter =
  APIQueries {..}
  where
    listClients' :<|> createClient' :<|> update :<|> get :<|> delete = api

    create clientInfo = createClient' clientInfo >>= returnResourceID . S.lookupResponseHeader @"Location"
      where
        returnResourceID :: S.ResponseHeader "Location" ResourceID -> SC.ClientM ResourceID
        returnResourceID (S.Header resourceID) = return resourceID
        returnResourceID S.MissingHeader = throwM MissingHeader
        returnResourceID (S.UndecodableHeader bs) = throwM UndecodableHeader

    list = listClients' Nothing

    getByName name =
      listClients' (Just name)
        >>= ( \case
                [x] -> return x
                [] -> throwM NoItemFound
                _ -> throwM TooManyItemsFound
            )
          . filter (\v -> nameFilter (resourceInfo v) == name)
    deleteByName name = getByName name >>= (delete . resourceID)

data APIQueries name t = APIQueries
  { list :: SC.ClientM [WithResourceID t],
    create :: t -> SC.ClientM ResourceID,
    update :: ResourceID -> WithResourceID t -> SC.ClientM S.NoContent,
    get :: ResourceID -> SC.ClientM (WithResourceID t),
    getByName :: name -> SC.ClientM (WithResourceID t),
    delete :: ResourceID -> SC.ClientM S.NoContent,
    deleteByName :: name -> SC.ClientM S.NoContent
  }

module UtilsSpec
  ( spec
  ) where

import qualified Test.Hspec                    as T
import qualified Utils                         as U

spec :: T.Spec
spec = do
  T.describe "splitOn" $ do
    T.it "returns nothing on empty list" $ U.joinTwo [] `T.shouldBe` Nothing
    T.it "returns nothing on list of one" $ U.joinTwo ["a"] `T.shouldBe` Nothing
    T.it "returns list of two" $ U.joinTwo ["a", "b"] `T.shouldBe` Just
      ("a", "b", "")
    T.it "returns rest on list of more than two"
      $            U.joinTwo ["a", "b", "c", "d"]
      `T.shouldBe` Just ("a", "b", "cd")

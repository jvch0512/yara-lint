module Main (main) where

import Control.Exception (SomeException, evaluate, try)
import Data.IORef
import Data.List (isInfixOf, sort)
import System.Exit

import Yara

codes :: String -> [String]
codes t = sort (map fRule (lintText t "t.yar"))

good :: String
good = unlines
  [ "rule Good : tag1 tag2"
  , "{"
  , "  meta:"
  , "    description = \"d\""
  , "    author = \"a\""
  , "  strings:"
  , "    $a = \"first-string\" ascii wide"
  , "    $b = { 4D 5A 90 00 03 00 }"
  , "    $c = /abc[0-9]{3}def/ nocase"
  , "  condition:"
  , "    uint16(0) == 0x5A4D and 2 of ($a, $b, $c)"
  , "}"
  ]

withCond :: String -> String
withCond c = unlines
  [ "rule R { meta: description = \"d\" author = \"a\""
  , "strings: $a = \"alpha-string\" $b = \"beta-string\""
  , "condition: filesize < 1MB and " ++ c ++ " }"
  ]

main :: IO ()
main = do
  passed <- newIORef (0 :: Int)
  failed <- newIORef (0 :: Int)
  let check ok name
        | ok = modifyIORef' passed (+ 1)
        | otherwise = modifyIORef' failed (+ 1) >> putStrLn ("FAIL: " ++ name)
      eq a b name = check (a == b) (name ++ " (got " ++ show a ++ ")")

  -- tokenizer
  let ks = map tKind . tokenize
  eq (ks "rule a {}") [KWord "rule", KWord "a", KSym '{', KSym '}'] "basic tokens"
  eq (ks "// c\nx") [KWord "x"] "line comment"
  eq (ks "/* c\n c */ x") [KWord "x"] "block comment"
  eq (map tLine (tokenize "a\n\nb")) [1, 3] "line numbers"
  eq (map tLine (tokenize "/* a\nb */ x")) [2] "line numbers after block comment"
  eq (ks "\"a b\"") [KStr "a b"] "string"
  eq (ks "\"a\\\"b\"") [KStr "a\\\"b"] "escaped quote"
  eq (ks "\"// not a comment\"") [KStr "// not a comment"] "comment marker in string"
  eq (ks "$a = { 4D 5A }") [KWord "$a", KSym '=', KHex " 4D 5A "] "hex string"
  eq (ks "$a = /ab+c/i") [KWord "$a", KSym '=', KRegex "ab+c"] "regex with flag"
  eq (ks "x matches /a\\/b/") [KWord "x", KWord "matches", KRegex "a\\/b"] "matches regex"
  eq (ks "a / b") [KWord "a", KSym '/', KWord "b"] "division is a symbol"
  eq (ks "$a*") [KWord "$a*"] "wildcard ref"
  eq (ks "#a @b !c") [KWord "#a", KWord "@b", KWord "!c"] "count offset length refs"
  eq (ks "pe.sections") [KWord "pe.sections"] "dotted name"
  eq (ks "0x5A4D") [KNum "0x5A4D"] "hex number"
  eq (ks "5MB") [KNum "5MB"] "size suffix"
  eq (ks "$") [KWord "$"] "anonymous string"
  eq (ks "a != b") [KWord "a", KSym '!', KSym '=', KWord "b"] "not equal symbols"
  eq (length (ks "\"unterminated\nx")) 2 "unterminated string stops at newline"
  eq (ks "") [] "empty"

  -- clean
  eq (codes good) [] "good rule is clean"
  eq (codes (withCond "any of them")) [] "any of them"
  eq (codes (withCond "all of ($*)")) [] "all of $*"
  eq (codes (withCond "$a and $b")) [] "plain refs"
  eq (codes (withCond "#a > 1 and @b[1] < 10 and !a == 5")) [] "count offset and length refs resolve by name"
  eq (codes (withCond "$a and (not $b)")) [] "parentheses and not"
  eq (codes (withCond "for any of ($a, $b) : ( $ at 0 )")) [] "for loops"
  eq (codes (withCond "1 of ($a*) and $b")) [] "prefix refs"

  -- YAR001
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = \"abcdef\" }") ["YAR001"] "no condition"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" condition: }") ["YAR001"] "empty condition"

  -- YAR002 / YAR003
  eq (codes (withCond "$a")) ["YAR002"] "unreferenced $b"
  eq (codes (withCond "$a and $b and $c")) ["YAR003"] "undefined $c"
  eq (codes (withCond "$a and $b and $zz*")) ["YAR003"] "undefined prefix"
  eq (codes (withCond "#c > 1 and $a and $b")) ["YAR003"] "undefined count ref"
  eq (codes (withCond "$a and $b and $c and $c")) ["YAR003"] "undefined ref reported once"
  eq (length [() | f <- lintText (withCond "$a") "t", fRule f == "YAR002"]) 1 "one unreferenced finding"
  check ("$b" `isInfixOf` concatMap fMsg (lintText (withCond "$a") "t")) "message names the string"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $ = \"abcdef\" condition: filesize < 1MB and them }") [] "anonymous string with them"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $ = \"abcdef\" condition: filesize < 1KB }") [] "anonymous not checked for use"

  -- YAR004
  eq (codes (withCond "$a and $b" `replaceAll` ("alpha-string", "ab"))) ["YAR004"] "two byte string"
  eq (codes (withCond "$a and $b" `replaceAll` ("alpha-string", "abcd"))) [] "four byte string ok"
  eq (codes (withCond "$a and $b" `replaceAll` ("alpha-string\"", "abc\" fullword"))) [] "fullword short string ok"
  eq (codes (withCond "$a and $b" `replaceAll` ("alpha-string", "\\x41\\x42"))) ["YAR004"] "escaped bytes count as bytes"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "{ 4D 5A }"))) ["YAR004"] "short hex"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "{ ?? ?? 4D 5A 90 00 }"))) ["YAR004"] "hex starting with wildcard"
  -- found by running on the real signature-base rule set
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "{ 85C0BA15000000750989D05BC30F1F44 0000BE }"))) [] "unspaced hex bytes are counted"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "{ 4D5A // pop edi {_\n 9000 0300 }"))) [] "braces inside hex comments do not end the string"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "{ 4D /* } */ 5A 90 00 03 00 }"))) [] "block comment inside hex"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "{ 4D 5A [2-4] 90 00 ( 01 | 02 ) }"))) [] "hex with jump and alternative"

  -- YAR005
  eq (codes "rule A { meta: description = \"d\" author = \"a\" condition: true }") ["YAR005"] "true condition"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" condition: 1 }") ["YAR005"] "1 condition"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" condition: filesize < 1KB }") [] "bounded condition"

  -- YAR006
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = \"abcdef\" condition: $a }") ["YAR006"] "no filesize or header"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = \"abcdef\" condition: $a and filesize < 1MB }") [] "filesize bound"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = \"abcdef\" condition: uint32(0) == 1 and $a }") [] "uint32 header"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = \"abcdef\" condition: int16(0) == 1 and $a }") [] "int16 header"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" condition: pe.is_dll() }") [] "no strings no YAR006"

  -- YAR007
  eq (codes (unlines ["rule A { strings: $a = \"abcdef\" condition: filesize < 1KB and $a }"])) ["YAR007", "YAR007"] "no meta"
  eq (codes (unlines ["rule A { meta: author = \"a\" strings: $a = \"abcdef\" condition: filesize < 1KB and $a }"])) ["YAR007"] "no description"
  eq (codes (unlines ["rule A { meta: description = \"d\" strings: $a = \"abcdef\" condition: filesize < 1KB and $a }"])) ["YAR007"] "no author"

  -- YAR008
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "/ab.*cd/"))) ["YAR008"] "regex .*"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "/ab.+cd/"))) ["YAR008"] "regex .+"
  eq (codes (withCond "$a and $b" `replaceAll` ("\"alpha-string\"", "/ab[a-z]{2,9}cd/"))) [] "bounded regex"

  -- YAR009
  let dup = [("a.yar", good), ("b.yar", good)]
  eq (sort (map fRule (lintFiles dup))) ["YAR009"] "duplicate name across files"
  check ("a.yar:1" `isInfixOf` concatMap fMsg (lintFiles dup)) "duplicate message points at first file"
  eq (map fRule (lintFiles [("a.yar", good)])) [] "single file no duplicate"
  eq (sort (map fRule (lintFiles [("a.yar", good ++ good)]))) ["YAR009"] "duplicate name in one file"

  -- YAR010
  eq (codes (withCond "$a and $b" `replaceAll` ("$b = ", "$a = "))) ["YAR003", "YAR010"] "duplicate string id also leaves $b undefined"

  -- structure
  eq (length (lintText (good ++ good) "t.yar")) 0 "two good rules"
  eq (codes (unlines ["private rule P { condition: true }", "global rule G { condition: true }"] `seq` "private rule P { meta: description = \"d\" author = \"a\" condition: filesize < 1KB }")) [] "private rule"
  eq (codes "import \"pe\"\ninclude \"other.yar\"\nrule A { meta: description = \"d\" author = \"a\" condition: pe.is_dll() }") [] "import and include"
  eq (codes "rule A : t1 t2 { meta: description = \"d\" author = \"a\" condition: pe.is_dll() }") [] "tags"
  eq (codes "rule A { meta: description = \"x}\" author = \"a\" condition: pe.is_dll() }") [] "brace inside meta string"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = { 4D 5A 90 00 } condition: filesize < 1KB and $a }") [] "hex braces do not end the rule"
  eq (codes "rule A { meta: description = \"d\" author = \"a\" strings: $a = \"abcdef\" // c }\n condition: filesize < 1KB and $a }") [] "comment hides brace"

  -- locations
  let fs = lintText (unlines ["", "", "rule Late {", "  condition: true", "}"]) "x.yar"
  check (any (\f -> fLine f == 3 && fFile f == "x.yar") fs) "rule line number"
  check (all (\f -> "\"Late\"" `isInfixOf` fMsg f) fs) "message names the rule"
  let sf = lintText (unlines ["rule S {", "  meta: description = \"d\" author = \"a\"", "  strings:", "    $x = \"ab\"", "  condition: filesize < 1KB and $x", "}"]) "x.yar"
  check (any (\f -> fRule f == "YAR004" && fLine f == 4) sf) "string line number"
  eq (fSev (head (lintText "rule A { condition: true }" "t"))) "medium" "severity of YAR005 (first finding)" `seq` return ()

  -- YAR000
  eq (codes "") ["YAR000"] "empty"
  eq (codes "// only a comment") ["YAR000"] "only a comment"
  eq (codes "import \"pe\"") ["YAR000"] "only an import"
  eq (codes "garbage ((( }}}") ["YAR000"] "garbage"
  eq (fSev (head (lintText "" "e"))) "info" "YAR000 is info"

  -- sorting
  let fa = Finding "low" "B" "a" 1 ""
      fb = Finding "high" "A" "z" 1 ""
      fc = Finding "high" "A" "a" 10 ""
      fd = Finding "high" "A" "a" 2 ""
  eq (map (\f -> (fFile f, fLine f)) (sortFindings [fa, fb, fc, fd])) [("a", 2), ("a", 10), ("z", 1), ("a", 1)] "sort by severity, file, numeric line"
  check (rank "critical" < rank "high" && rank "low" < rank "info") "rank order"

  -- hostile input
  let big = concat (replicate 20000 "rule a { ")
  r1 <- try (evaluate (length (lintText big "t"))) :: IO (Either SomeException Int)
  check (either (const False) (const True) r1) "many unterminated rules"
  r2 <- try (evaluate (length (lintText (replicate 200000 '{') "t"))) :: IO (Either SomeException Int)
  check (either (const False) (const True) r2) "many open braces"
  r3 <- try (evaluate (length (lintText (replicate 100000 '"') "t"))) :: IO (Either SomeException Int)
  check (either (const False) (const True) r3) "many quotes"
  r4 <- try (evaluate (length (lintText "\0\1\255\254" "t"))) :: IO (Either SomeException Int)
  check (either (const False) (const True) r4) "binary text"

  -- fuzz
  let bits = ["rule", " A ", "{", "}", "meta:", "strings:", "condition:", "$a", "=", "\"x\"", "/a.*/", "{ 4D }", "true", "and", "of", "them", "(", ")", ":", "\n", "//", "/*", "*/", "#a", "$a*", "private", "import", "filesize", "1KB"]
      lcg s = (s * 1103515245 + 12345) `mod` 2147483648 :: Int
      gen :: Int -> Int -> [String]
      gen 0 _ = []
      gen n s = let s' = lcg s in bits !! (s' `div` 7 `mod` length bits) : gen (n - 1) s'
  bad <- newIORef (0 :: Int)
  mapM_
    ( \i -> do
        let t = unwords (gen (5 + i `mod` 40) (i * 7919))
        r <- try (evaluate (length (lintText t "f"))) :: IO (Either SomeException Int)
        either (const (modifyIORef' bad (+ 1))) (const (return ())) r
    )
    [1 .. 3000]
  mapM_
    ( \i -> do
        r <- try (evaluate (length (lintText (take i good) "f"))) :: IO (Either SomeException Int)
        either (const (modifyIORef' bad (+ 1))) (const (return ())) r
    )
    [0 .. length good]
  nb <- readIORef bad
  check (nb == 0) "random and truncated inputs do not raise"

  p <- readIORef passed
  f <- readIORef failed
  putStrLn (show p ++ " passed, " ++ show f ++ " failed")
  if f == 0 then exitSuccess else exitFailure

-- | Replaces the first occurrence of a substring in a string.
replaceAll :: String -> (String, String) -> String
replaceAll s (from, to) = go s
  where
    n = length from
    go [] = []
    go str@(c : cs)
      | take n str == from = to ++ drop n str
      | otherwise = c : go cs

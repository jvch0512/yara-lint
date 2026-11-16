module Yara
  ( Finding (..)
  , Tok (..)
  , Kind (..)
  , tokenize
  , lintText
  , lintFiles
  , sortFindings
  , rank
  ) where

import Data.Char (isAlpha, isAlphaNum, isDigit, isHexDigit, isSpace)
import Data.List (isInfixOf, isPrefixOf, isSuffixOf, nub, sortBy)
import qualified Data.Map.Strict as M
import Data.Ord (comparing)

data Finding = Finding
  { fSev :: String
  , fRule :: String
  , fFile :: String
  , fLine :: Int
  , fMsg :: String
  } deriving (Eq, Show)

rank :: String -> Int
rank "critical" = 0
rank "high" = 1
rank "medium" = 2
rank "low" = 3
rank _ = 4

sortFindings :: [Finding] -> [Finding]
sortFindings = sortBy (comparing (\f -> (rank (fSev f), fFile f, fLine f, fRule f, fMsg f)))

------------------------------------------------------------------ tokenizer

data Kind
  = KWord String
  | KStr String
  | KRegex String
  | KHex String
  | KNum String
  | KSym Char
  deriving (Eq, Show)

data Tok = Tok {tLine :: Int, tKind :: Kind} deriving (Eq, Show)

countNl :: String -> Int
countNl = length . filter (== '\n')

tokenize :: String -> [Tok]
tokenize = go 1 Nothing
  where
    go :: Int -> Maybe Kind -> String -> [Tok]
    go _ _ [] = []
    go ln prev (c : r)
      | c == '\n' = go (ln + 1) prev r
      | isSpace c = go ln prev r
    go ln prev ('/' : '/' : r) = go ln prev (dropWhile (/= '\n') r)
    go ln prev ('/' : '*' : r) =
      let (body, rest) = blockComment r
       in go (ln + countNl body) prev rest
    go ln _ ('"' : r) =
      let (body, rest) = readStr r
       in emit ln (KStr body) rest
    go ln prev ('/' : r)
      | regexCtx prev =
          let (body, rest) = readRegex r
              (flags, rest') = span (`elem` "is") rest
           in emit ln (KRegex body) (flags `seq` rest')
    go ln (Just (KSym '=')) ('{' : r) =
      let (body, nls, rest') = readHex r
       in Tok ln (KHex body) : go (ln + nls) (Just (KHex body)) rest'
    go ln _ s@(c : r)
      | c `elem` "$#@!" =
          let (name, rest) = span (\x -> isAlphaNum x || x == '_') r
              (star, rest') = if "*" `isPrefixOf` rest then ("*", drop 1 rest) else ("", rest)
           in if null name && null star
                then (if c == '$' then emit ln (KWord "$") r else emit ln (KSym c) r)
                else emit ln (KWord (c : name ++ star)) rest'
      | isAlpha c || c == '_' =
          let (w, rest) = span (\x -> isAlphaNum x || x == '_' || x == '.') s
           in emit ln (KWord w) rest
      | isDigit c =
          let (w, rest) = span (\x -> isAlphaNum x || x == '.') s
           in emit ln (KNum w) rest
      | otherwise = emit ln (KSym c) r

    emit ln k rest = Tok ln k : go ln (Just k) rest

    regexCtx (Just (KSym '=')) = True
    regexCtx (Just (KWord "matches")) = True
    regexCtx _ = False

    -- Hex strings may carry // and /* */ comments (often disassembly with braces in them), so skip those up to the real closing brace.
    readHex :: String -> (String, Int, String)
    readHex [] = ([], 0, [])
    readHex ('}' : r) = ([], 0, r)
    readHex ('/' : '/' : r) =
      let (_, rest) = break (== '\n') r
          (b, n, rest') = readHex rest
       in (b, n, rest')
    readHex ('/' : '*' : r) =
      let (body, rest) = blockComment r
          (b, n, rest') = readHex rest
       in (replicate (countNl body) '\n' ++ b, n + countNl body, rest')
    readHex ('\n' : r) = let (b, n, rest) = readHex r in ('\n' : b, n + 1, rest)
    readHex (x : r) = let (b, n, rest) = readHex r in (x : b, n, rest)

    blockComment :: String -> (String, String)
    blockComment [] = ([], [])
    blockComment ('*' : '/' : r) = ([], r)
    blockComment (x : r) = let (b, rest) = blockComment r in (x : b, rest)

    readStr :: String -> (String, String)
    readStr [] = ([], [])
    readStr s@('\n' : _) = ([], s)
    readStr ('\\' : x : r)
      | x /= '\n' = let (b, rest) = readStr r in ('\\' : x : b, rest)
    readStr ('"' : r) = ([], r)
    readStr (x : r) = let (b, rest) = readStr r in (x : b, rest)

    readRegex :: String -> (String, String)
    readRegex [] = ([], [])
    readRegex s@('\n' : _) = ([], s)
    readRegex ('\\' : x : r)
      | x /= '\n' = let (b, rest) = readRegex r in ('\\' : x : b, rest)
    readRegex ('/' : r) = ([], r)
    readRegex (x : r) = let (b, rest) = readRegex r in (x : b, rest)

------------------------------------------------------------------ parser

data SKind = SText | SRegex | SHex deriving (Eq, Show)

data Str = Str
  { sId :: String
  , sKind :: SKind
  , sBody :: String
  , sMods :: [String]
  , sLine :: Int
  } deriving (Show)

data Rule = Rule
  { rName :: String
  , rLine :: Int
  , rMeta :: [String]
  , rStrings :: [Str]
  , rCond :: Maybe [Tok]
  } deriving (Show)

parseRules :: [Tok] -> [Rule]
parseRules [] = []
parseRules (Tok _ (KWord "rule") : Tok ln (KWord name) : rest) =
  let afterTags = dropWhile (\t -> tKind t /= KSym '{') rest
   in case afterTags of
        [] -> [Rule name ln [] [] Nothing]
        (_ : bodyAndRest) ->
          let (body, remaining) = takeBody 0 bodyAndRest
           in parseBody name ln body : parseRules remaining
parseRules (Tok _ (KWord "import") : _ : rest) = parseRules rest
parseRules (Tok _ (KWord "include") : _ : rest) = parseRules rest
parseRules (_ : rest) = parseRules rest

takeBody :: Int -> [Tok] -> ([Tok], [Tok])
takeBody _ [] = ([], [])
takeBody d (t : ts) = case tKind t of
  KSym '{' -> let (b, r) = takeBody (d + 1) ts in (t : b, r)
  KSym '}' | d == 0 -> ([], ts)
           | otherwise -> let (b, r) = takeBody (d - 1) ts in (t : b, r)
  _ -> let (b, r) = takeBody d ts in (t : b, r)

sectionWords :: [String]
sectionWords = ["meta", "strings", "condition"]

splitSections :: [Tok] -> [(String, [Tok])]
splitSections ts = case ts of
  (Tok _ (KWord w) : Tok _ (KSym ':') : rest)
    | w `elem` sectionWords ->
        let (body, more) = breakStart rest in (w, body) : splitSections more
  (_ : rest) -> splitSections rest
  [] -> []

breakStart :: [Tok] -> ([Tok], [Tok])
breakStart [] = ([], [])
breakStart ts@(Tok _ (KWord w) : Tok _ (KSym ':') : _)
  | w `elem` sectionWords = ([], ts)
breakStart (t : r) = let (a, b) = breakStart r in (t : a, b)

parseBody :: String -> Int -> [Tok] -> Rule
parseBody name ln toks =
  let secs = splitSections toks
      sec k = [ts | (w, ts) <- secs, w == k]
      meta = concatMap metaKeys (sec "meta")
      strs = concatMap parseStrings (sec "strings")
      cond = case sec "condition" of
        [] -> Nothing
        (c : _) -> Just c
   in Rule name ln meta strs cond

metaKeys :: [Tok] -> [String]
metaKeys (Tok _ (KWord k) : Tok _ (KSym '=') : _ : rest) = k : metaKeys rest
metaKeys (_ : rest) = metaKeys rest
metaKeys [] = []

isDef :: [Tok] -> Bool
isDef (Tok _ (KWord ('$' : _)) : Tok _ (KSym '=') : _) = True
isDef _ = False

parseStrings :: [Tok] -> [Str]
parseStrings (Tok ln (KWord i@('$' : _)) : Tok _ (KSym '=') : v : rest) =
  let (mods, more) = breakDef rest
      kind = case tKind v of
        KStr _ -> Just (SText, strBody (tKind v))
        KRegex b -> Just (SRegex, b)
        KHex b -> Just (SHex, b)
        _ -> Nothing
      ws = [w | Tok _ (KWord w) <- mods]
   in case kind of
        Just (k, b) -> Str i k b ws ln : parseStrings more
        Nothing -> parseStrings (v : rest)
parseStrings (_ : rest) = parseStrings rest
parseStrings [] = []

strBody :: Kind -> String
strBody (KStr s) = s
strBody _ = ""

breakDef :: [Tok] -> ([Tok], [Tok])
breakDef [] = ([], [])
breakDef ts@(t : rest)
  | isDef ts = ([], ts)
  | otherwise = let (a, b) = breakDef rest in (t : a, b)

------------------------------------------------------------------ rules

data Ref = Exact String | Prefix String deriving (Eq, Show)

condRefs :: [Tok] -> ([Ref], Bool)
condRefs toks =
  let ws = [w | Tok _ (KWord w) <- toks]
      them = "them" `elem` ws
      refs = concatMap toRef ws
   in (refs, them)
  where
    toRef "$" = []
    toRef (c : n)
      | c `elem` "$#@!" && not (null n) =
          if "*" `isSuffixOf` n then [Prefix ('$' : init n)] else [Exact ('$' : n)]
    toRef _ = []

textLen :: String -> Int
textLen [] = 0
textLen ('\\' : 'x' : a : b : r) | isHexDigit a && isHexDigit b = 1 + textLen r
textLen ('\\' : _ : r) = 1 + textLen r
textLen (_ : r) = 1 + textLen r

hexFixedBytes :: String -> Int
hexFixedBytes s = pairs (filter (\c -> isHexDigit c || c == '?') (stripJumps s))
  where
    -- drop [n-m] jumps, then count two-digit pairs with no wildcard nibble; spacing is optional in YARA hex strings
    stripJumps [] = []
    stripJumps ('[' : r) = stripJumps (drop 1 (dropWhile (/= ']') r))
    stripJumps (c : r) = c : stripJumps r
    pairs (a : b : r) = (if isHexDigit a && isHexDigit b then 1 else 0) + pairs r
    pairs _ = 0

hexStartsWild :: String -> Bool
hexStartsWild s = case dropWhile isSpace s of
  ('?' : _) -> True
  ('[' : _) -> True
  _ -> False

lintRule :: FilePath -> Rule -> [Finding]
lintRule file r = metaF ++ condF ++ dupF ++ strF ++ matchAllF ++ scanF ++ refF
  where
    q s = "\"" ++ s ++ "\""
    n = rName r
    ln = rLine r
    f sev code msg = Finding sev code file ln (q n ++ ": " ++ msg)
    fl sev code l msg = Finding sev code file l (q n ++ ": " ++ msg)
    strs = rStrings r
    ids = [sId s | s <- strs, sId s /= "$"]

    metaF =
      [f "low" "YAR007" "meta has no description" | "description" `notElem` rMeta r]
        ++ [f "low" "YAR007" "meta has no author" | "author" `notElem` rMeta r]

    condF = case rCond r of
      Nothing -> [f "high" "YAR001" "rule has no condition"]
      Just [] -> [f "high" "YAR001" "rule has an empty condition"]
      Just _ -> []

    dupF =
      [ fl "high" "YAR010" (sLine s) ("string " ++ sId s ++ " is defined more than once")
      | (s, i) <- zip strs [0 :: Int ..]
      , sId s /= "$"
      , sId s `elem` [sId t | t <- take i strs]
      ]

    strF = concatMap oneStr strs
    oneStr s = case sKind s of
      SText
        | textLen (sBody s) < 4 && "fullword" `notElem` sMods s ->
            [fl "medium" "YAR004" (sLine s) ("string " ++ sId s ++ " is shorter than four bytes")]
      SHex
        | hexFixedBytes (sBody s) < 4 ->
            [fl "medium" "YAR004" (sLine s) ("hex string " ++ sId s ++ " has fewer than four fixed bytes")]
        | hexStartsWild (sBody s) ->
            [fl "medium" "YAR004" (sLine s) ("hex string " ++ sId s ++ " starts with a wildcard")]
      SRegex
        | ".*" `isInfixOf` sBody s || ".+" `isInfixOf` sBody s ->
            [fl "medium" "YAR008" (sLine s) ("regex " ++ sId s ++ " has an unbounded .* or .+")]
      _ -> []

    kinds = maybe [] (map tKind) (rCond r)
    matchAllF = case kinds of
      [KWord "true"] -> [f "medium" "YAR005" "condition is always true"]
      [KNum "1"] -> [f "medium" "YAR005" "condition is always true"]
      _ -> []

    scanF = case rCond r of
      Just c
        | not (null strs)
        , not (any bounds [w | Tok _ (KWord w) <- c]) ->
            [f "low" "YAR006" "no filesize bound or file header check, every file is scanned in full"]
      _ -> []
    bounds w = w == "filesize" || w `elem` ["uint8", "uint16", "uint32", "uint16be", "uint32be", "int8", "int16", "int32"]

    refF = case rCond r of
      Nothing -> []
      Just c ->
        let (refs, them) = condRefs c
            matches ref i = case ref of
              Exact e -> e == i
              Prefix p -> p `isPrefixOf` i
            used i = them || any (`matches` i) refs
            unused = [s | s <- strs, sId s /= "$", not (used (sId s))]
            undefinedRefs =
              [ ref
              | ref <- refs
              , not (any (matches ref) ids)
              ]
         in [fl "high" "YAR002" (sLine s) ("string " ++ sId s ++ " is not referenced in the condition") | s <- unused]
              ++ [f "high" "YAR003" ("condition uses " ++ showRef ref ++ " which is not defined") | ref <- dedupe undefinedRefs]
    showRef (Exact e) = e
    showRef (Prefix p) = p ++ "*"
    dedupe = nub

lintText :: String -> FilePath -> [Finding]
lintText text file =
  let rules = parseRules (tokenize text)
   in if null rules
        then [Finding "info" "YAR000" file 0 "no YARA rules found, ignored"]
        else concatMap (lintRule file) rules

-- | Lints several files in order and reports rule names that repeat.
lintFiles :: [(FilePath, String)] -> [Finding]
lintFiles files = sortFindings (go M.empty files)
  where
    go _ [] = []
    go seen ((file, text) : rest) =
      let rules = parseRules (tokenize text)
          (dups, seen') = foldl step ([], seen) rules
          step (acc, m) r = case M.lookup (rName r) m of
            Just (pf, pl) ->
              ( acc ++ [Finding "medium" "YAR009" file (rLine r) ("\"" ++ rName r ++ "\" is already defined at " ++ pf ++ ":" ++ show pl)]
              , m
              )
            Nothing -> (acc, M.insert (rName r) (file, rLine r) m)
       in lintText text file ++ dups ++ go seen' rest

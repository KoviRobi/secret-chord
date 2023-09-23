: here dp @ ;
: source input-buffer @ input-size @ ;
: true -1 ;
: false 0 ;
: immediate true latest @ immediate! ;
: recursive false latest @ hidden! ; immediate
: char word drop c@ ;
: space 32 ;
: \
  [ here ]
    ?refill 0= (if) [ here 1 c, ] (;) [ here over - swap c! ]
    source >in @ > (if) [ here 1 c, ]
      >in @ + c@ 10 = (if) [ here 1 c, ] (;) [ here over - swap c! ]
      1 >in +!
    [ here over - swap c! ]
  (again) [ here swap - c, ] ; immediate
: (
  [ here ]
    ?refill 0= (if) [ here 1 c, ] (;) [ here over - swap c! ]
    source >in @ > (if) [ here 1 c, ]
      >in @ + c@
      1 >in +!
      [ char ) literal ] = (if) [ here 1 c, ] (;) [ here over - swap c! ]
    [ here over - swap c! ]
  (again) [ here swap - c, ] ; immediate
: "
  1 >in +! \ Skip space
  here 0
  [ here ]
    ?refill 0= (if) [ here 1 c, ] (;) [ here over - swap c! ]
    source >in @ > (if) [ here 1 c, ]
      >in @ + c@
      1 >in +!
      dup 34 = (if) [ here 1 c, ] drop (;) [ here over - swap c! ]
          c,
      1+
    [ here over - swap c! ]
  (again) [ here swap - c, ] ;
: abort .s 0 sp ! quit ;
: (fail) r> dup uleb128@ rot + swap type abort ;
: (defer) r> uleb128@ drop interpreter>code >r ;
: (assert) 0= (if) [ here 1 c, ] (defer) (fail)
           [ here over - swap c! ]
           r> dup uleb128@ + + >r ;
: ' word find 0= (if) [ here 0 c, ]
  [ char " literal ] emit type [ char " literal ] emit
  (fail) [ 0 c, "  not found
" swap 1- c! ]
  [ here over - swap c! ] ;
: postpone ' compile, ; immediate
true ' compile, immediate!
true ' literal immediate!
: ['] ' postpone literal ; immediate
: postpost ' postpone literal ['] compile, postpone compile, ; immediate

: if postpost (if) here 1 c, ; immediate
: then here over - dup 128 < (assert) [ 0 c, " Jump too long for if
" swap 1- c! ]
       swap c! ; immediate
: else postpost (else)
       1 c, here over - dup 128 < (assert) [ 0 c, " Jump too long for if
" swap 1- c! ] swap c!
       here 1- ; immediate

: begin here ; immediate
: again postpost (again) here swap - uleb128, drop ; immediate

: unimplemented (fail) [ 0 c, " Not implemented
" swap 1- c! ] ;
: create : postpone [ postpone recursive ; \ TODO
: defer create postpost (defer) postpost unimplemented ;
: is ( xt -- ) here swap ' ( stashed-here value-xt name-xt )
  >interpreter interpreter>code dp !
  postpost (defer)
  postpone compile,
  dp ! ;

: 2drop drop drop ;
: 2dup over over ;

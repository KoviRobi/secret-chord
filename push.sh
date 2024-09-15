#!/bin/sh

set -eux

git push origin \
  +refs/heads/1-introduction:refs/heads/1-introduction \
  +refs/heads/1-introduction-base:refs/heads/1-introduction-base \
  +refs/heads/2-numbers-in-detail:refs/heads/2-numbers-in-detail \
  +refs/heads/2-numbers-in-detail-base:refs/heads/2-numbers-in-detail-base \
  +refs/heads/3-going-forth:refs/heads/3-going-forth \
  +refs/heads/3-going-forth-base:refs/heads/3-going-forth-base \
  +refs/heads/reviewforth:refs/heads/reviewforth \
  +refs/notes/devtools/discuss:refs/notes/devtools/discuss \
  +refs/notes/devtools/reviews:refs/notes/devtools/reviews

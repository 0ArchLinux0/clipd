# Next Base — Phase 2 Ready List

## Must fix before v0.2.0
- [x] session.rs tests: fix Incoming.await + my_meta + assert types
- [x] CLI serve: verify real clipboard update from peer (run local loop)
- [x] Add CI .github/workflows/ci.yml (fmt + clippy + test)

## After that — Phase 2 priorities
- [ ] iOS clipboard constraints / Watch gateway (phone-as-gateway)
- [ ] True LWW / vector clocks per device (extend LamportClock)
- [ ] Relay fallback (iroh / small derper) for remote sync
- [ ] Optional tray / menu-bar thin clients (not headless)
- [ ] Push repo to GitHub / GitLab (user provides remote URL)

## Repository / Push
Repo is at ~/code_repo/clipd (git init + commits).
To push: create remote repo, then:
  git remote add origin <url>
  git push -u origin master

## v0.2.0 closeout (commits since prior tag)
- a4f29d0  test fix: rcgen ED25519 + tx.finish race + dup-lamport re-sign
- a1cdcaf  cli: 'clipd smoke' for end-to-end local loop verification
- 52facf9  ci: GitHub Actions workflow + clippy/fmt cleanup
- All 10 unit tests pass; 'clipd smoke' passes locally on macOS.
- CI will gate future merges on fmt + clippy (-D warnings) + test.

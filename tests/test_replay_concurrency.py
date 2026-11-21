"""Shared in-process replay-store concurrency regressions."""
from concurrent.futures import ThreadPoolExecutor
from threading import Event, Lock

import pytest
import kya.replay as replay
from tests.test_replay import make_credential
from kya import ReplayStore, authorize_purchase, generate_keypair
from fastapi.testclient import TestClient
from service.app import create_app


@pytest.mark.parametrize('route', ['store', 'authorize', 'http'])
def test_concurrent_same_presentation_has_one_winner(monkeypatch, route):
    # Hold the first writer after its absence check, while a second caller
    # tries the same pair. The old unlocked store lets the second writer
    # normalize and record before the first writer resumes: both return True.
    first_normalizing = Event()
    second_normalizing = Event()
    release_first = Event()
    counter_lock = Lock()
    count = 0
    original = replay._normalize_time

    def controlled_normalize(value, field):
        nonlocal count
        with counter_lock:
            count += 1
            position = count
        if position == 1:
            first_normalizing.set()
            assert release_first.wait(5)
        else:
            second_normalizing.set()
        return original(value, field)

    private, public = generate_keypair()
    credential = make_credential(private)
    store = ReplayStore()
    client = TestClient(create_app(public, replay_store=store))

    def present():
        if route == 'store':
            return store.check_and_record('credential-1', 'order-1')
        if route == 'authorize':
            return authorize_purchase(
                public, credential, 10.0, 'electronics',
                replay_store=store, presentation_id='order-1',
            )[0]
        return client.post('/checkout', json={
            'credential': credential, 'amount_usd': 10.0,
            'category': 'electronics', 'presentation_id': 'order-1',
        }).json()['accepted']

    monkeypatch.setattr(replay, '_normalize_time', controlled_normalize)
    with ThreadPoolExecutor(max_workers=2) as pool:
        first = pool.submit(present)
        try:
            assert first_normalizing.wait(5)
            second = pool.submit(present)
            # With the fix the second caller waits for the store lock instead
            # of entering normalization. Timeout is only a scheduling aid;
            # correctness is asserted from both actual results below.
            second_normalizing.wait(0.2)
        finally:
            release_first.set()
        assert sorted([first.result(5), second.result(5)]) == [False, True]
    assert len(store) == 1

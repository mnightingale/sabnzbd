#!/usr/bin/python3 -OO
# Copyright 2007-2026 by The SABnzbd-Team (sabnzbd.org)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

"""
tests.test_pipelining - Test the pipelining depth controller
"""

from itertools import pairwise
from types import SimpleNamespace

import pytest
import sabctools

import sabnzbd

from sabnzbd.pipelining import (
    DWELL,
    PipeliningMonitor,
    EMA_ALPHA,
    LOWER_AFTER,
    REPROBE_INTERVAL,
    PipelineSample,
    ServerPipelineController,
    log_tcp_info,
)

START = 10_000.0


def make_sample(now=START, configured=10, responses=20, transfer_time=0.075, round_trip=0.08, **kwargs):
    return PipelineSample(
        now=now,
        configured=configured,
        responses=responses,
        transfer_time=transfer_time,
        round_trips=[round_trip] * 4 if round_trip else [],
        throughput=kwargs.pop("throughput", 10_000_000.0),
        **kwargs,
    )


def settle(controller, count=120, start=START, step=2.0, **kwargs):
    """Feed identical windows until the controller has walked all the way to its answer.

    Each step needs both its agreeing windows and a full dwell, so reaching a depth
    several steps away takes a while."""
    kwargs.setdefault("configured", controller.depth)
    depth = controller.depth
    for index in range(count):
        depth = controller.sample(make_sample(now=start + index * step, **kwargs))
    return depth


class TestWantedDepth:
    def test_covers_a_round_trip_longer_than_a_transfer(self):
        """250 ms of latency over 75 ms articles needs four requests to cover the gap"""
        controller = ServerPipelineController(configured=10)

        assert settle(controller, transfer_time=0.075, round_trip=0.25) == 5

    def test_two_is_enough_when_the_transfer_dwarfs_the_round_trip(self):
        """A link that is the bottleneck still wants one spare request, and only one"""
        controller = ServerPipelineController(configured=10)

        assert settle(controller, transfer_time=3.75, round_trip=0.03) == 2

    def test_never_exceeds_what_is_configured(self):
        controller = ServerPipelineController(configured=2)

        assert settle(controller, transfer_time=0.05, round_trip=1.0) == 2

    def test_never_goes_below_one(self):
        controller = ServerPipelineController(configured=1)

        assert settle(controller, transfer_time=5.0, round_trip=0.001) == 1

    def test_falls_back_to_the_handshake_when_no_round_trip_was_seen(self):
        controller = ServerPipelineController(configured=10)

        assert settle(controller, round_trip=None, connect_time=0.25, transfer_time=0.075) == 5

    def test_holds_when_there_is_no_latency_signal_at_all(self):
        controller = ServerPipelineController(configured=6)

        assert settle(controller, round_trip=None, connect_time=None) == 6


class TestGuards:
    def test_a_quiet_window_changes_nothing(self):
        controller = ServerPipelineController(configured=10)

        settle(controller, responses=1, transfer_time=0.075, round_trip=0.08)

        assert controller.depth == 10
        assert controller.transfer_time is None

    def test_receiver_limited_freezes_the_depth(self):
        """Slow reading inflates the transfer time, which would otherwise read as a
        reason to shrink the pipeline that was never at fault"""
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=0.075, round_trip=0.25)
        before = controller.depth

        settle(controller, start=START + 100, transfer_time=10.0, round_trip=0.001, receiver_limited=True)

        assert controller.depth == before

    def test_receiver_limited_does_not_lower_either(self):
        controller = ServerPipelineController(configured=4)

        settle(controller, count=40, transfer_time=10.0, round_trip=0.001, receiver_limited=True)

        assert controller.depth == 4

    def test_a_window_with_no_transfer_time_is_ignored(self):
        controller = ServerPipelineController(configured=10)

        controller.sample(make_sample(transfer_time=0.0))

        assert controller.transfer_time is None


class TestSteadiness:
    def test_moves_one_step_at_a_time(self):
        controller = ServerPipelineController(configured=10)
        depths = []

        for index in range(LOWER_AFTER * 3):
            depths.append(controller.sample(make_sample(now=START + index * DWELL, transfer_time=3.0)))

        steps = [abs(b - a) for a, b in pairwise(depths)]
        assert max(steps) <= 1

    def test_dwell_blocks_an_immediate_reversal(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=3.0)
        lowered = controller.depth

        for index in range(LOWER_AFTER):
            controller.sample(make_sample(now=controller.settled_at + 0.1 * index, transfer_time=0.01, round_trip=1.0))

        assert controller.depth == lowered

    def test_one_dissenting_window_resets_the_count(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=3.0)
        depth = controller.depth
        now = controller.settled_at + DWELL * 4

        for index in range(LOWER_AFTER - 1):
            controller.sample(make_sample(now=now + index, transfer_time=0.01, round_trip=1.0))
        controller.sample(make_sample(now=now + LOWER_AFTER, transfer_time=3.0))

        assert controller.depth == depth

    def test_does_not_flap_when_the_wanted_depth_oscillates(self):
        """The measurement sitting on a boundary must not turn into a moving depth"""
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=0.0755, round_trip=0.1)
        settled = controller.depth
        controller.probe_at = START + 1_000_000
        changes = 0
        previous = settled

        for index in range(200):
            transfer = 0.1 if index % 2 else 0.051
            depth = controller.sample(
                make_sample(now=START + 1000 + index * 2.0, transfer_time=transfer, round_trip=0.1)
            )
            if depth != previous:
                changes += 1
                previous = depth

        assert changes == 0, f"settled at {settled}, ended at {previous}"


class TestProbing:
    def test_probes_deeper_once_the_interval_passes(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=3.0)
        lowered = controller.depth

        controller.sample(make_sample(now=START + REPROBE_INTERVAL * 2, transfer_time=3.0))

        assert controller.depth == lowered + 1
        assert controller.probing_from == lowered

    def test_a_probe_that_gains_nothing_is_given_up(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=3.0)
        lowered = controller.depth
        probe_time = START + REPROBE_INTERVAL * 2
        controller.sample(make_sample(now=probe_time, transfer_time=3.0, throughput=10_000_000.0))

        controller.sample(make_sample(now=probe_time + DWELL + 1, transfer_time=3.0, throughput=10_000_000.0))

        assert controller.depth == lowered
        assert controller.probing_from is None

    def test_a_probe_that_pays_off_is_kept(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=3.0)
        lowered = controller.depth
        probe_time = START + REPROBE_INTERVAL * 2
        controller.sample(make_sample(now=probe_time, transfer_time=3.0, throughput=10_000_000.0))

        controller.sample(make_sample(now=probe_time + DWELL + 1, transfer_time=3.0, throughput=20_000_000.0))

        assert controller.depth == lowered + 1
        assert controller.probing_from is None


class TestSmoothing:
    def test_a_steady_reading_converges_on_itself(self):
        controller = ServerPipelineController(configured=10)

        settle(controller, count=50, transfer_time=0.2)

        assert controller.transfer_time == pytest.approx(0.2, rel=1e-3)

    def test_a_step_is_most_of_the_way_there_after_the_time_constant(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, count=50, transfer_time=1.0)

        for index in range(round(1 / EMA_ALPHA)):
            controller.sample(make_sample(now=START + 200 + index, transfer_time=2.0))

        assert controller.transfer_time == pytest.approx(1.63, abs=0.1)

    def test_reset_forgets_what_was_measured(self):
        controller = ServerPipelineController(configured=10)
        settle(controller, transfer_time=0.2)

        controller.reset()

        assert controller.transfer_time is None
        assert controller.round_trips == []


class FakeConnection:
    """Just the counters the sampler reads, and the socket it looks for"""

    def __init__(
        self,
        responses=20,
        transfer_total=1.5,
        idle_total=0.5,
        round_trip_total=0.32,
        round_trip_count=4,
        nntp=None,
    ):
        self.nntp = nntp
        self.responses_seen = responses
        self.transfer_total = transfer_total
        self.idle_total = idle_total
        self.round_trip_total = round_trip_total
        self.round_trip_count = round_trip_count


def fake_server(configured=10, connections=()):
    return SimpleNamespace(
        id="server",
        host="news.example.com",
        addrinfo=SimpleNamespace(connection_time=0.02),
        busy_threads=set(connections),
        idle_threads=set(),
        pipelining_requests=lambda: configured,
        effective_pipelining=configured,
        pipeline_controller=ServerPipelineController(configured),
    )


class TestMonitor:
    def test_drains_the_connection_counters(self, mocker):
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(server_bps={"server": 1e7}))
        connection = FakeConnection()
        server = fake_server(connections=[connection])

        PipeliningMonitor().sample_server(server, now=START, limited=False)

        assert connection.responses_seen == 0
        assert connection.transfer_total == 0.0
        assert connection.round_trip_count == 0

    def test_a_window_of_measurements_reaches_the_controller(self, mocker):
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(server_bps={"server": 1e7}))
        server = fake_server(connections=[FakeConnection()])

        PipeliningMonitor().sample_server(server, now=START, limited=False)

        # 1.5 s of transfer over 20 responses, and 0.32 s of round trip over 4
        assert server.pipeline_controller.transfer_time == pytest.approx(0.075)
        assert server.pipeline_controller.round_trips == [(START, pytest.approx(0.08))]

    def test_idle_fraction_is_of_the_time_the_connection_was_engaged(self, mocker):
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(server_bps={"server": 1e7}))
        server = fake_server(connections=[FakeConnection(transfer_total=1.5, idle_total=0.5)])

        PipeliningMonitor().sample_server(server, now=START, limited=False)

        assert server.pipeline_controller.idle_fraction == pytest.approx(0.25)

    def test_a_server_with_no_traffic_is_left_alone(self, mocker):
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(server_bps={}))
        server = fake_server(connections=[FakeConnection(responses=0, transfer_total=0.0, round_trip_count=0)])

        PipeliningMonitor().sample_server(server, now=START, limited=False)

        assert server.effective_pipelining == 10
        assert server.pipeline_controller.transfer_time is None

    def test_the_depth_reaches_the_server(self, mocker):
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(server_bps={"server": 1e7}))
        server = fake_server(connections=[FakeConnection()])
        monitor = PipeliningMonitor()

        for index in range(120):
            server.busy_threads = {FakeConnection(transfer_total=60.0, round_trip_total=0.04)}
            monitor.sample_server(server, now=START + index * 2.0, limited=False)

        assert server.effective_pipelining == 2

    def test_a_limited_window_reaches_the_controller_as_such(self, mocker):
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(server_bps={"server": 1e7}))
        server = fake_server(connections=[FakeConnection(transfer_total=60.0)])

        PipeliningMonitor().sample_server(server, now=START, limited=True)

        assert server.effective_pipelining == 10
        assert server.pipeline_controller.transfer_time is None


class TestReceiverLimited:
    def test_assembler_backpressure_counts(self, mocker):
        mocker.patch.object(sabnzbd, "Assembler", create=True, new=SimpleNamespace(delay=lambda: 0.1))

        assert PipeliningMonitor.receiver_limited() is True

    def test_hitting_the_bandwidth_limit_counts(self, mocker):
        mocker.patch.object(sabnzbd, "Assembler", create=True, new=SimpleNamespace(delay=lambda: 0.0))
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(bps=1e7))
        mocker.patch.object(
            sabnzbd,
            "Downloader",
            create=True,
            new=SimpleNamespace(bandwidth_limit=1e6, receive_busy_fraction=lambda: 0.0),
        )

        assert PipeliningMonitor.receiver_limited() is True

    def test_saturated_receive_threads_count(self, mocker):
        mocker.patch.object(sabnzbd, "Assembler", create=True, new=SimpleNamespace(delay=lambda: 0.0))
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(bps=0.0))
        mocker.patch.object(
            sabnzbd,
            "Downloader",
            create=True,
            new=SimpleNamespace(bandwidth_limit=0, receive_busy_fraction=lambda: 0.95),
        )

        assert PipeliningMonitor.receiver_limited() is True

    def test_an_unconstrained_downloader_is_not_limited(self, mocker):
        mocker.patch.object(sabnzbd, "Assembler", create=True, new=SimpleNamespace(delay=lambda: 0.0))
        mocker.patch.object(sabnzbd, "BPSMeter", create=True, new=SimpleNamespace(bps=1e7))
        mocker.patch.object(
            sabnzbd,
            "Downloader",
            create=True,
            new=SimpleNamespace(bandwidth_limit=0, receive_busy_fraction=lambda: 0.1),
        )

        assert PipeliningMonitor.receiver_limited() is False


class TestTcpSnapshot:
    def test_reads_one_of_the_connections(self, mocker):
        info = {"source": "linux", "rtt": 19000}
        mocker.patch.object(sabctools, "tcp_info", return_value=info)
        server = fake_server()
        server.busy_threads = {FakeConnection(nntp=SimpleNamespace(sock=object()))}

        assert PipeliningMonitor.tcp_snapshot(server) is info

    def test_skips_connections_that_have_no_socket(self, mocker):
        mocker.patch.object(sabctools, "tcp_info", return_value=None)
        server = fake_server()
        server.busy_threads = {FakeConnection(nntp=None)}

        assert PipeliningMonitor.tcp_snapshot(server) is None

    def test_a_server_with_nothing_connected_reports_nothing(self):
        assert PipeliningMonitor.tcp_snapshot(fake_server()) is None

    def test_logging_tolerates_the_fields_a_platform_cannot_supply(self):
        log_tcp_info(
            "news.example.com",
            {
                "source": "macos",
                "rtt": 19000,
                "min_rtt": None,
                "rcv_wnd": 131712,
                "bytes_reordered": 0,
                "packets_reordered": None,
                "bytes_retrans_out": 0,
            },
        )

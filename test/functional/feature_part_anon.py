#!/usr/bin/env python3
# Copyright (c) 2017-2019 The Particl Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from test_framework.test_capricoinplus import CapricoinPlusTestFramework
from test_framework.util import assert_raises_rpc_error, connect_nodes_bi


class AnonTest(CapricoinPlusTestFramework):
    def set_test_params(self):
        self.setup_clean_chain = True
        self.num_nodes = 3
        self.extra_args = [ ['-debug','-noacceptnonstdtxn','-reservebalance=10000000'] for i in range(self.num_nodes)]

    def skip_test_if_missing_module(self):
        self.skip_if_no_wallet()

    def setup_network(self, split=False):
        self.add_nodes(self.num_nodes, extra_args=self.extra_args)
        self.start_nodes()

        connect_nodes_bi(self.nodes, 0, 1)
        connect_nodes_bi(self.nodes, 0, 2)
        self.sync_all()

    def run_test(self):
        nodes = self.nodes

        ro = nodes[0].extkeyimportmaster('abandon baby cabbage dad eager fabric gadget habit ice kangaroo lab absorb')
        assert(ro['account_id'] == 'aaaZf2qnNr5T7PWRmqgmusuu5ACnBcX2ev')
        assert(nodes[0].getwalletinfo()['total_balance'] == 100000)
        txnHashes = []

        ro = nodes[1].extkeyimportmaster('drip fog service village program equip minute dentist series hawk crop sphere olympic lazy garbage segment fox library good alley steak jazz force inmate')
        sxAddrTo1_1 = nodes[1].getnewstealthaddress('lblsx11')
        assert(sxAddrTo1_1 == 'TetbYTGv5LiqyFiUD3a5HHbpSinQ9KiRYDGAMvRzPfz4RnHMbKGAwDr1fjLGJ5Eqg1XDwpeGyqWMiwdK3qM3zKWjzHNpaatdoHVzzA')

        sxAddrTo0_1 = nodes[0].getnewstealthaddress('lblsx01')


        txnHash = nodes[0].sendparttoanon(sxAddrTo1_1, 1, '', '', False, 'node0 -> node1 p->a')
        txnHashes.append(txnHash)

        txnHash = nodes[0].sendparttoblind(sxAddrTo0_1, 1000, '', '', False, 'node0 -> node0 p->b')
        txnHashes.append(txnHash)

        txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 1')
        txnHashes.append(txnHash)

        txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 2')
        txnHashes.append(txnHash)

        txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 100, '', '', False, 'node0 -> node1 b->a 3')
        txnHashes.append(txnHash)

        txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a 4')
        txnHashes.append(txnHash)

        for k in range(5):
            txnHash = nodes[0].sendparttoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 p->a')
            txnHashes.append(txnHash)
        for k in range(10):
            txnHash = nodes[0].sendblindtoanon(sxAddrTo1_1, 10, '', '', False, 'node0 -> node1 b->a')
            txnHashes.append(txnHash)

        for h in txnHashes:
            assert(self.wait_for_mempool(nodes[1], h))

        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[1].listtransactions('*', 100)))
        assert('node0 -> node1 b->a 4' in self.dumpj(nodes[0].listtransactions('*', 100)))

        self.stakeBlocks(2)

        block1_hash = nodes[1].getblockhash(1)
        ro = nodes[1].getblock(block1_hash)
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])


        txnHash = nodes[1].sendanontoanon(sxAddrTo0_1, 1, '', '', False, 'node1 -> node0 a->a')
        txnHashes = [txnHash,]

        assert(self.wait_for_mempool(nodes[0], txnHash))

        ro = nodes[0].listtransactions()
        #print("0 listtransactions ", json.dumps(ro, indent=4, default=self.jsonDecimal))

        self.stakeBlocks(1)

        ro = nodes[1].getblock(nodes[1].getblockhash(3))
        for txnHash in txnHashes:
            assert(txnHash in ro['tx'])

        assert(nodes[1].anonoutput()['lastindex'] == 28)

        txnHash = nodes[1].sendanontoanon(sxAddrTo0_1, 101, '', '', False, 'node1 -> node0 a->a', 5, 1)
        txnHashes = [txnHash,]

        assert(self.wait_for_mempool(nodes[0], txnHash))

        txnHash = nodes[1].sendanontoanon(sxAddrTo0_1, 0.1, '', '', False, '', 5, 2)
        txnHashes = [txnHash,]

        assert(self.wait_for_mempool(nodes[0], txnHash))


        ro = nodes[1].getwalletinfo()
        assert(ro['anon_balance'] > 10)

        outputs = [{'address':sxAddrTo0_1, 'amount':10, 'subfee':True},]
        ro = nodes[1].sendtypeto('anon', 'part', outputs, 'comment_to', 'comment_from', 4, 32, True)
        assert(ro['bytes'] > 0)

        txnHash = nodes[1].sendtypeto('anon', 'part', outputs)
        txnHashes = [txnHash,]

        self.log.info('Test filtertransactions with type filter')
        ro = nodes[1].filtertransactions({ 'type': 'anon', 'count': 20 })
        assert(len(ro) > 2)
        for t in ro:
            foundA = False
            for o in t['outputs']:
                if 'type' in o and o['type'] == 'anon':
                    foundA = True
                    break
            assert((foundA is True) or (t['type_in'] == 'anon'))

        self.log.info('Test unspent with address filter')
        unspent_filtered = nodes[1].listunspentanon(1, 9999, [sxAddrTo1_1])
        assert(unspent_filtered[0]['label'] == 'lblsx11')

        self.log.info('Test permanent lockunspent')
        unspent = nodes[1].listunspentanon()
        assert(nodes[1].lockunspent(False, [unspent[0]], True) == True)
        assert(nodes[1].lockunspent(False, [unspent[1]], True) == True)
        assert(len(nodes[1].listlockunspent()) == 2)
        # Restart node
        self.sync_all()
        self.stop_node(1)
        self.start_node(1, self.extra_args[1])
        assert(len(nodes[1].listlockunspent()) == 2)
        assert(len(nodes[1].listunspentanon()) < len(unspent))
        assert(nodes[1].lockunspent(True, [unspent[0]]) == True)
        assert_raises_rpc_error(-8, 'Invalid parameter, expected locked output', nodes[1].lockunspent, True, [unspent[0]])
        assert(len(nodes[1].listunspentanon()) == len(unspent)-1)
        assert(nodes[1].lockunspent(True) == True)
        assert(len(nodes[1].listunspentanon()) == len(unspent))
        assert(nodes[1].lockunspent(True) == True)


if __name__ == '__main__':
    AnonTest().main()

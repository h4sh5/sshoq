package ssh3

import (
	"sync"

	"github.com/h4sh5/sshoq/util"
	"github.com/quic-go/quic-go/http3"
	"github.com/rs/zerolog/log"
)

type ControlStreamID = uint64

type conversationsManager struct {
	connection    http3.StreamCreator
	conversations map[ControlStreamID]*Conversation
	lock          sync.Mutex
}

func newConversationManager(connection http3.StreamCreator) *conversationsManager {
	return &conversationsManager{connection: connection, conversations: make(map[ControlStreamID]*Conversation)}
}

func (m *conversationsManager) addConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	m.conversations[uint64(conversation.controlStream.StreamID())] = conversation
}

func (m *conversationsManager) getConversation(id ControlStreamID) (*Conversation, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	conv, ok := m.conversations[id]
	return conv, ok
}

func (m *conversationsManager) removeConversation(conversation *Conversation) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.conversations, uint64(conversation.controlStream.StreamID()))
}

type channelsManager struct {
	channels            map[util.ChannelID]Channel
	danglingDgramQueues map[util.ChannelID]*util.DatagramsQueue
	lock                sync.Mutex
}

func newChannelsManager() *channelsManager {
	return &channelsManager{channels: make(map[util.ChannelID]Channel), danglingDgramQueues: make(map[util.ChannelID]*util.DatagramsQueue)}
}

func (m *channelsManager) addChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	if dgramsQueue, ok := m.danglingDgramQueues[channel.ChannelID()]; ok {
		channel.setDgramQueue(dgramsQueue)
		delete(m.danglingDgramQueues, channel.ChannelID())
	}
	m.channels[util.ChannelID(channel.ChannelID())] = channel
}

// maxDanglingDatagramQueues bounds how many channels may have datagrams waiting for them
// in one conversation. A datagram may legitimately arrive before the channel it carries has
// been opened - which is why they are kept - but the channel ID inside it is picked by the
// peer, so without a bound a peer spraying datagrams with made-up IDs would make this
// allocate one queue per ID, and never give any of it back.
const maxDanglingDatagramQueues = 100

// danglingDatagramQueueLen is how many datagrams are kept for a single unknown channel.
const danglingDatagramQueueLen = 10

// queueDanglingDatagram remembers a datagram received for a channel which does not exist
// yet, so that it is handed over to that channel when it shows up.
func (m *channelsManager) queueDanglingDatagram(id util.ChannelID, datagram []byte) {
	m.lock.Lock()
	defer m.lock.Unlock()
	// let's first check if a channel has recently been added
	if channel, ok := m.channels[id]; ok {
		channel.addDatagram(datagram)
		return
	}
	queue, ok := m.danglingDgramQueues[id]
	if !ok {
		if len(m.danglingDgramQueues) >= maxDanglingDatagramQueues {
			log.Warn().Msgf("dropping datagram for unknown channel %d: %d channels already have datagrams waiting",
				uint64(id), maxDanglingDatagramQueues)
			return
		}
		queue = util.NewDatagramsQueue(danglingDatagramQueueLen)
		m.danglingDgramQueues[id] = queue
	}
	// a queue which is already full loses the datagram, as it would with a real channel
	// whose reader fell behind: it must never block the one reading the socket
	queue.Add(datagram)
}

func (m *channelsManager) getChannel(id util.ChannelID) (Channel, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()
	channel, ok := m.channels[id]
	return channel, ok
}

func (m *channelsManager) removeChannel(channel Channel) {
	m.lock.Lock()
	defer m.lock.Unlock()
	delete(m.channels, util.ChannelID(channel.ChannelID()))
}

func (m *channelsManager) onChannelClose(channel Channel) {
	m.removeChannel(channel)
}

package nft
import "syscall"

const (
	NFT_MSG_NEWTABLE = iota
	NFT_MSG_GETTABLE
	NFT_MSG_DELTABLE
	NFT_MSG_NEWCHAIN
	NFT_MSG_GETCHAIN
	NFT_MSG_DELCHAIN
	NFT_MSG_NEWRULE
	NFT_MSG_GETRULE
	NFT_MSG_DELRULE
	NFT_MSG_NEWSET
	NFT_MSG_GETSET
	NFT_MSG_DELSET
	NFT_MSG_NEWSETELEM
	NFT_MSG_GETSETELEM
	NFT_MSG_DELSETELEM
	NFT_MSG_NEWGEN
	NFT_MSG_GETGEN
	NFT_MSG_TRACE
	NFT_MSG_NEWOBJ
	NFT_MSG_GETOBJ
	NFT_MSG_DELOBJ
	NFT_MSG_GETOBJ_RESET
	NFT_MSG_MAX
)

const (
	MNL_CB_ERROR  =  -1
	MNL_CB_STOP   =  0
	MNL_CB_OK     =  1
)

//const (
//	NLMSG_ERROR = 0x2 //syscall.NLMSG_ERROR
//)

const (
	//NLMSG_MIN_TYPE = syscall.NLMSG_MIN_TYPE
	NFNL_MSG_BATCH_BEGIN = syscall.NLMSG_MIN_TYPE
	NFNL_MSG_BATCH_END = syscall.NLMSG_MIN_TYPE+1
)

const (
	//NLA_TYPE_MASK should be ^(syscall.NLA_F_NESTED | syscall.NLA_F_NET_BYTEORDER)
	//use unmask to skip constant overflow
	NLA_TYPE_UNMASK = syscall.NLA_F_NESTED | syscall.NLA_F_NET_BYTEORDER
)

const (
    SizeofNfgenmsg      = 4 //maybe syscall.NLMSG_ALIGNTO
	NFNL_SUBSYS_NFTABLES = 10
)

//nf_tables data netlink attributes
const (
	NFTA_DATA_UNSPEC = iota
	NFTA_DATA_VALUE
	NFTA_DATA_VERDICT
	__NFTA_DATA_MAX
)
const (
	NFTA_DATA_MAX = __NFTA_DATA_MAX + 1
)

//nf_tables set element netlink attributes
const (
	NFTA_SET_ELEM_UNSPEC = iota
	NFTA_SET_ELEM_KEY
	NFTA_SET_ELEM_DATA
	NFTA_SET_ELEM_FLAGS
	NFTA_SET_ELEM_TIMEOUT
	NFTA_SET_ELEM_EXPIRATION
	NFTA_SET_ELEM_USERDATA
	NFTA_SET_ELEM_EXPR
	NFTA_SET_ELEM_PAD
	NFTA_SET_ELEM_OBJREF
	__NFTA_SET_ELEM_MAX
)

//nf_tables set element list netlink attributes
const (
	NFTA_SET_ELEM_LIST_UNSPEC = iota
	NFTA_SET_ELEM_LIST_TABLE
	NFTA_SET_ELEM_LIST_SET
	NFTA_SET_ELEM_LIST_ELEMENTS
	NFTA_SET_ELEM_LIST_SET_ID
	__NFTA_SET_ELEM_LIST_MAX
)
const (
	NFTA_SET_ELEM_LIST_MAX = (__NFTA_SET_ELEM_LIST_MAX - 1)
)


//nf_tables table netlink attributes
const (
	NFTA_TABLE_UNSPEC = iota
	NFTA_TABLE_NAME
	NFTA_TABLE_FLAGS
	NFTA_TABLE_USE
	__NFTA_TABLE_MAX
)

const (
	MNL_TYPE_UNSPEC = iota
	MNL_TYPE_U8
	MNL_TYPE_U16
	MNL_TYPE_U32
	MNL_TYPE_U64
	MNL_TYPE_STRING
	MNL_TYPE_FLAG
	MNL_TYPE_MSECS
	MNL_TYPE_NESTED
	MNL_TYPE_NESTED_COMPAT
	MNL_TYPE_NUL_STRING
	MNL_TYPE_BINARY
	MNL_TYPE_MAX
)

const (
    NFTA_LIST_UNPEC = iota
    NFTA_LIST_ELEM
    __NFTA_LIST_MAX
)

const (
	NFTA_SET_UNSPEC = iota
	NFTA_SET_TABLE
	NFTA_SET_NAME
	NFTA_SET_FLAGS
	NFTA_SET_KEY_TYPE
	NFTA_SET_KEY_LEN
	NFTA_SET_DATA_TYPE
	NFTA_SET_DATA_LEN
	NFTA_SET_POLICY
	NFTA_SET_DESC
	NFTA_SET_ID
	NFTA_SET_TIMEOUT
	NFTA_SET_GC_INTERVAL
	NFTA_SET_USERDATA
	NFTA_SET_PAD
	NFTA_SET_OBJ_TYPE
	__NFTA_SET_MAX
)

const (
	NFTA_SET_MAX = (__NFTA_SET_MAX - 1)
)

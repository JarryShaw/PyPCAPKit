/**
 * @file reassembly.hpp
 * @author Jarry Shaw (jarryshaw@icloud.com)
 * @brief Base Class for Reassembly
 * @version 0.16.3
 * @date 2022-12-20
 *
 * @copyright Copyright (c) 2017-2022
 *
 * :mod:`pcapkit.foundation.reassembly.reassembly` contains
 * :class:`~pcapkit.foundation.reassembly.reassembly.Reassembly` only,
 * which is an abstract base class for all reassembly classes,
 * bases on algorithms described in :rfc:`791` and :rfc:`815`,
 * implements datagram reassembly of IP and TCP packets.
 */

#include <limits.h>
#include <stdio.h>
#include <sstream>
#include <string>
#include <string.h>
#include <vector>

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

using namespace pybind11::literals;
namespace py = pybind11;

py::module_ mod_protocols_protocol = py::module::import("pcapkit.protocols.protocol");
py::module_ mod_corekit_infoclass = py::module::import("pcapkit.corekit.infoclass");

py::object Protocol = mod_protocols_protocol.attr("Protocol");
py::object Info = mod_corekit_infoclass.attr("Info");

template <typename PT, typename DT, typename IT, typename BT>
class Reassembly
{
    // Internal data storage for cached properties.
    py::dict __cached__;

    // Strict mode flag.
    bool _strflg;
    // New datagram flag.
    bool _newflg;

    // Dict buffer field.
    std::map<IT, BT> _buffer;
    // List reassembled datagram.
    std::vector<DT> _dtgram;

public:
    Reassembly(bool strict = true);
    // ~Reassembly();

    /* Properties. */

    // Protocol name of current reaassembly object.
    virtual std::string name() = 0;
    // Total number of reassembled packets.
    std::size_t count();
    // Reassembled datagram.
    py::tuple datagram();
    // Protocol of current reassembly object.
    virtual Protocol protocol();

    /* Methods. */

    // Reassembly procedure.
    virtual void reassembly(PT info);
    // Submit reassembled payload.
    virtual std::vector<DT> submit(BT buf, py::kwargs kwargs);
    // Fetch datagram.
    py::tuple fetch();
    // Return datagram index.
    std::size_t index(std::size_t pkt_num);
    // Run automatically.
    void run(std::vector<PT> packets);
};

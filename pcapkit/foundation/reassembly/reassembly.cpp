#include "./reassembly.hpp"

template <typename PT, typename DT, typename IT, typename BT>
Reassembly<PT, DT, IT, BT>::Reassembly(bool strict) : _strflg(strict)
{
    this->__cached__ = py::dict();

    this->_buffer = std::map<IT, BT>();
    this->_dtgram = std::vector<DT>();
}

template <typename PT, typename DT, typename IT, typename BT>
std::size_t Reassembly<PT, DT, IT, BT>::count()
{
    std::size_t cached, ret;

    if (this->_newflg) {
        this->__cached__.clear();
        this->_newflg = false;
    }

    if ((cached = this->__cached__.get("count")) != nullptr) {
        return cached;
    }

    ret = this->_dtgram.size();
    this->__cached__["count"] = ret;
    return ret;
}

template <typename PT, typename DT, typename IT, typename BT>
py::tuple Reassembly<PT, DT, IT, BT>::datagram()
{
    if (!this->_buffer.empty()) {
        return this->fetch();
    }
    return py::make_tuple(this->_dtgram);
}

template <typename PT, typename DT, typename IT, typename BT>
py::tuple Reassembly<PT, DT, IT, BT>::fetch()
{
    py::tuple cached, ret;

    if (this->_newflg) {
        this->__cached__.clear();
        this->_newflg = false;
    }

    if ((cached = this->__cached__.get("fetch")) != nullptr) {
        return cached;
    }

    std::vector<DT> temp_dtgram;
    for (auto &it : this->_buffer) {
        temp_dtgram.push_back(it.second);
    }

    ret = py::make_tuple(this->_dtgram);
    this->__cached__["fetch"] = ret;
    return ret;
}

template <typename PT, typename DT, typename IT, typename BT>
std::size_t Reassembly<PT, DT, IT, BT>::index(std::size_t pkt_num)
{
    for (std::size_t i = 0; i < this->_dtgram.size(); i++) {
        for (size_t j = 0; j < this->_dtgram[i].size(); j++) {
            if (this->_dtgram[i][j] == pkt_num) {
                return i;
            }
        }
    }
    return -1;
}

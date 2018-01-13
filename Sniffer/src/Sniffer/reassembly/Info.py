class Info(dict):
    """Turn dictionaries into object-like instances."""

    def __new__(cls, dict_=None, **kwargs):
        self = super().__new__(cls, **kwargs)

        if dict_ is None:
            return self

        if isinstance(dict_, Info):
            self = copy.deepcopy(dict_)
            return self

        for key in dict_:
            if isinstance(dict_[key], Info):
                self.__dict__[key] = dict_[key]
            elif isinstance(dict_[key], dict):
                self.__dict__[key] = Info(dict_[key])
            else:
                if isinstance(key, str):
                    key = key.replace('-', '_')
                self.__dict__[key] = dict_[key]

        return self

    def __repr__(self):
        list_ = []
        for (key, value) in self.__dict__.items():
            str_ = '{key}={value}'.format(key=key, value=str(value))
            list_.append(str_)
        repr_ = 'Info(' + ', '.join(list_) + ')'
        return repr_

    __str__ = __repr__

    def __getitem__(self, key):
        return self.__dict__[key]

    def __contains__(self, name):
        return (name in self.__dict__)

    def __setattr__(self, name, value):
        raise AttributeError('can\'t set attribute')

    def __delattr__(self, name):
        raise AttributeError('can\'t delete attribute')

    def infotodict(self):
        dict_ = {}
        for key in self.__dict__:
            if isinstance(self.__dict__[key], Info):
                dict_[key] = self.__dict__[key].infotodict()
            else:
                dict_[key] = self.__dict__[key]
        return dict_
import logging
import logging.handlers


class Logger:
    def __init__(self, logger_name, filename, level=None, fmt=None):
        self._logger = logging.getLogger(logger_name)
        self._filename = filename
        self._format = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(message)s'
        )
        self._level = self.set_level(logging.DEBUG)

        if fmt is not None:
            self.set_format(fmt)
        if level is not None:
            self.set_level(level)

    def set_level(self, level):
        self._level = level
        self._logger.setLevel(self._level)
        return level

    def set_format(self, fmt='%(asctime)s [%(levelname)s] %(message)s'):
        self._format = logging.Formatter(fmt)

    def add_handler(self, handler):
        handler.setLevel(self._level)
        handler.setFormatter(self._format)
        self._logger.addHandler(handler)

    def set_handelrs(self, rotate_handler_size=0, console_out=False):
        if console_out:
            self.add_handler(logging.StreamHandler())
        if rotate_handler_size != 0:
            self.add_handler(
                logging.handlers.RotatingFileHandler(
                    self._filename,
                    maxBytes=rotate_handler_size
                )
            )
        else:
            self.add_handler(
                logging.FileHandler(self._filename, mode='w')
            )

    def get_logger(self):
        return self._logger


if __name__ == '__main__':
    lg = Logger(__name__, f'../logs/{__name__}.log')
    lg.set_handelrs(100, False)
    logger = lg.get_logger()
    logger.info('qewwqwqeqe')
    logger.debug('qwewqeqwe')
    logger.debug('qwewqeqwe')
    logger.debug('qwewqeqwe')
    logger.debug('qwewqeqwe')
    logger.debug('qwewqeqwe')
    logger.debug('qwewqeqwe')
    logger.debug('qwewqeqwe')
    print(logger)

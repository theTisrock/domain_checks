# ipv4 & ipv6 helper classes:
# reponsible for validating ip4 and ip6 bytes responses & mutating ip6 bytes responses into traditional ip6 string format.


class V6:
    """A helper class that validates, converts, or parses IPv6 address data from unbound."""

    @staticmethod
    def is_valid(ipv6_bytes):
        """Takes an input of type 'bytes' and ensures that all 128 bits are present."""
        if not isinstance(ipv6_bytes, type(b'')):
            raise TypeError("The input value must of type 'bytes'")

        return len(ipv6_bytes) == 16

    @staticmethod
    def bytes_to_hexadectet(ipv6_bytes):
        """Accepts ipv6 bytes. Returns a compressed ipv6 bytes in a hexadecimal string."""
        if not isinstance(ipv6_bytes, type(b's')):
            raise TypeError("Input type: " + str(type(ipv6_bytes)) + " Requires type: " + str(type(b'')))

        result = ""

        index = 0
        for i in ipv6_bytes:

            is_trailing = index % 2 == 1
            is_leading = index % 2 == 0
            at_end = index == 15
            is_leading_zero = False
            if is_trailing and index >= 1:
                is_leading_zero = ipv6_bytes[index-1] == 0

            if i == 0 and is_trailing and ipv6_bytes[index-1] != 0:  # if I am a trailing zero
                result += "00"
            elif i == 0 and is_trailing and ipv6_bytes[index-1] == 0:
                result += "0"
            elif i == 0:
                result += ""
            elif i < 16 and is_leading:  # even is front
                result += str(hex(i)[2:])
            elif i < 16 and is_trailing and at_end:
                result += str(hex(i)[2:])
            elif i < 16 and is_trailing and is_leading_zero:
                result += str(hex(i)[2:])
            elif i < 16 and is_trailing:
                result += "0" + str(hex(i)[2:])
            elif i >= 16:
                result += str(hex(i)[2:])

            if is_trailing and not at_end:
                result += ":"
            index += 1

        return V6._compress_colon_span(result)

    @staticmethod
    def _compress_colon_span(string):  # helper for bytes_to_hexadectets
        """Takes an ipv6 string in hexadecimal.
        Attempts to cut all ':' between the span of zeros in a series. span = [beg, end, beg, end... etc].
        Assumes list len is even. May need to throw an exception!!!!
        returns a compressed ipv6 formatted string. Not intended for public use."""
        colonspan_list_tuples = V6._colon_span_indices(string)

        if colonspan_list_tuples is None:
            return string  # unchanged

        result = ""
        for start, stop in colonspan_list_tuples:
            result += string[:start + 1] + string[stop:]

        return result

    @staticmethod
    def _colon_span_indices(string):  # helper to _compress_colon_span: "ff:::::::ff" to "ff::ff"
        """Records indices of ipv6 colon spans that cover a series of implied zeros.
        Should always return an even length list [beg, end, beg, end...].
        Allows _compress_colon_span to parse and cut ipv6 colons in a series.
        Not intended for public use."""
        if string is None or len(string) < 3:
            return None

        colonspan_list_tuples = []

        length = len(string)
        beg, end, cur = 0, 0, 0

        while (cur < length):  # traverse string across
            # find beginning
            have_distance = (length - 1) - cur >= 2  # keeps from out of bounds
            three_colons = False
            if have_distance:
                three_colons = string[cur] == ":" and string[cur + 1] == ":" and string[cur + 2] == ":"
            beg = cur  # beg must be first occurance

            compressible = have_distance and three_colons  # remainder of string is potentially compressible

            if compressible:
                for i in range(cur + 2, length):  # dns_state_analysis subsequence of ":"
                    if i == length - 1:  # stop at end of string
                        if string[i] != ":":
                            end = i - 1
                        else:
                            end = i
                        cur = length
                        colonspan_list_tuples.append((beg, end))
                        break
                    elif string[i] != ":":  # not at end and current char not ":"
                        end = i - 1  # previous char is the ending ":" in the previous sequence
                        colonspan_list_tuples.append((beg, end))  # record beg, end sequence
                        # now we have [beg, end] sequence; pick up at i on next iteration
                        cur = end  # will be incremented at bottom of while loop
                        break
                    else:
                        continue

            cur += 1

        if len(colonspan_list_tuples) == 0:
            colonspan_list_tuples = None

        return colonspan_list_tuples


class V4:
    """A helper class that validates IPv4 address responses from unbound."""
    @staticmethod
    def is_valid(ipv4_address):
        """Accepts ipv4_address as bytes. Ensures address isn't more or less than 4 bytes."""
        if not isinstance(ipv4_address, type(b'\x00')):
            raise TypeError("Input must be in bytes")
        IPV4_LEN = 4  # 4 bytes == 32 bits
        return len(ipv4_address) == IPV4_LEN

# end

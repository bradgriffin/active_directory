#-- license
#
#  Based on original code by Justin Mecham and James Hunt
#  at http://rubyforge.org/projects/activedirectory
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#++ license

module ActiveDirectory
  module FieldType
    class SID
      # Converts a binary SID to a string in S-R-I-S-S... format.
      #
      def self.decode(data)
        sid = []
        sid << data[0].unpack('b').first.to_s
       
        rid = ""
        (6).downto(1) do |i|
          rid += byte2hex(data[i,1][0])
        end
        sid << rid.to_i.to_s
       
        sid += data.unpack("bbbbbbbbV*")[8..-1]
        "S-" + sid.join('-')
      end

      # Converts a string in S-R-I-S-S... format back to a binary SID.
      #
      def self.encode(string)
        string_addr = [string].pack('p*').unpack('L')[0]
        sid_ptr  = 0.chr * 4

        sid_len = GetLengthSid(sid_ptr.unpack('L')[0])
        sid_buf = 0.chr * sid_len

        sid_buf
      end

      def self.byte2hex(b)
        ret = '%x' % (b.unpack('*h').first.to_i & 0xff)
        ret = '0' + ret if ret.length < 2
        ret
      end
    end
  end
end
# name: discourse-passwords-phpbb
# version: 0.0.1
# authors: Régis Hanol

class SaltedMD5
  class << self
    ITOA64 ||= "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"

    def settings(hash)
      {
        count: 1 << ITOA64.index(hash[3]),
        salt: hash[4...12],
        full: hash[0...12],
      }
    end

    def encode64(input, count)
      r = ""
      i = 0

      loop do
        value = input[i].ord
        i += 1

        r << ITOA64[value & 0x3F]

        value |= input[i].ord << 8 if i < count

        r << ITOA64[(value >> 6) & 0x3F]

        break if i >= count
        i += 1

        value |= input[i].ord << 16 if i < count

        r << ITOA64[(value >> 12) & 0x3F]

        break if i >= count
        i += 1

        r << ITOA64[(value >> 18) & 0x3F]

        break if i >= count
      end

      r
    end

    def compute_hash(password, s)
      h = Digest::MD5.digest(s[:salt] + password)
      s[:count].times { h = Digest::MD5.digest(h + password) }
      s[:full] + encode64(h, 16)
    end

    def check_hash(password, hash)
      compute_hash(password, settings(hash)) == hash
    end
  end
end

after_initialize do

  module ::MigratedPassword

    def confirm_password?(password)
      return true if super
      return false unless self.custom_fields.has_key?("import_pass")

      if SaltedMD5.check_hash(password, self.custom_fields["import_pass"])
        self.password = password
        self.custom_fields.delete("import_pass")
        return save
      end

      false
    end

  end

  class ::User
    prepend MigratedPassword
  end

end
